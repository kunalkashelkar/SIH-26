from pydantic import BaseModel

class CWEDefinition(BaseModel):
    cwe_id: str
    name: str
    description: str

CWE_CATALOG: dict[str, CWEDefinition] = {
    "SQLI": CWEDefinition(
        cwe_id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description="The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command."
    ),
    "XSS": CWEDefinition(
        cwe_id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."
    ),
    "IDOR": CWEDefinition(
        cwe_id="CWE-639",
        name="Authorization Bypass Through User-Controlled Key",
        description="The system's authorization functionality does not prevent one user from accessing, modifying, or deleting records or objects belonging to another user by changing an identifier key."
    ),
    "AUTH_BYPASS": CWEDefinition(
        cwe_id="CWE-287",
        name="Improper Authentication",
        description="When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."
    ),
    "OPEN_REDIRECT": CWEDefinition(
        cwe_id="CWE-601",
        name="URL Redirection to Untrusted Site ('Open Redirect')",
        description="A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect."
    ),
    "TYPE_CONFUSION": CWEDefinition(
        cwe_id="CWE-843",
        name="Access of Resource Using Incompatible Type ('Type Confusion')",
        description="The program allocates or initializes a resource using one type, but subsequently accesses that resource using a type that is incompatible with the original type."
    ),
    "INPUT_VALIDATION": CWEDefinition(
        cwe_id="CWE-20",
        name="Improper Input Validation",
        description="The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."
    )
}
