from pydantic import BaseModel
from typing import Optional

class RemediationRule(BaseModel):
    category: str
    explanation_template: str
    impact_template: str
    remediation_template: str
    prevention_guidance: str

REMEDIATION_RULES: dict[str, RemediationRule] = {
    "SQLI": RemediationRule(
        category="SQLI",
        explanation_template="Parameter '{parameter}' in {endpoint} was demonstrated to modify backend database queries when special SQL characters were injected.",
        impact_template="An unauthorized attacker could read sensitive database records, bypass authentication, modify data, or execute arbitrary database commands.",
        remediation_template="1. Use parameterized queries (prepared statements) or Object-Relational Mappers (ORMs) for all database operations.\n2. Ensure user input in parameter '{parameter}' is never concatenated directly into SQL query strings.\n3. Apply principle of least privilege to database connection accounts.",
        prevention_guidance="```python\n# Vulnerable:\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\n\n# Secure (Parameterized):\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n```"
    ),
    "XSS": RemediationRule(
        category="XSS",
        explanation_template="Parameter '{parameter}' in {endpoint} reflects untrusted input directly into the HTML document without adequate contextual encoding.",
        impact_template="An attacker can execute arbitrary JavaScript in the context of the victim's session, enabling session hijacking, credential theft, or unauthorized actions.",
        remediation_template="1. Contextually encode all user-supplied data in parameter '{parameter}' before rendering it in the HTML body, attributes, or script blocks.\n2. Implement a strict Content Security Policy (CSP) with nonce-based script execution.\n3. Set `HttpOnly` and `SameSite=Strict/Lax` flags on all sensitive session cookies.",
        prevention_guidance="```javascript\n// Vulnerable:\nelement.innerHTML = userMessage;\n\n// Secure:\nelement.textContent = userMessage;\n```"
    ),
    "IDOR": RemediationRule(
        category="IDOR",
        explanation_template="Parameter '{parameter}' in {endpoint} permits direct access to backend object identifiers without validating whether the active session owns the resource.",
        impact_template="Attackers can view, update, or delete records belonging to other tenants or users simply by cycling through identifier values.",
        remediation_template="1. Enforce record-level authorization checks on every request to {endpoint}.\n2. Verify `current_user.id == resource.owner_id` prior to returning or modifying object state.\n3. Use cryptographically random UUIDv4 or indirect mapping references instead of sequential integer IDs.",
        prevention_guidance="```python\n# Secure Record Authorization Pattern:\nitem = await db.get_item(item_id)\nif item.owner_id != current_user.id and not current_user.is_admin:\n    raise HTTPException(status_code=403, detail=\"Access denied\")\n```"
    ),
    "AUTH_BYPASS": RemediationRule(
        category="AUTH_BYPASS",
        explanation_template="Endpoint {endpoint} failed to properly verify authentication credentials or token claims before granting access to privileged resources.",
        impact_template="Unauthenticated attackers can assume user identities, access administrative controls, and compromise the integrity of application data.",
        remediation_template="1. Centralize authentication middleware across all protected routes.\n2. Reject default or blank credential submissions.\n3. Implement cryptographically verified session tokens (JWT with asymmetric signing or server-side session stores).",
        prevention_guidance="```python\n# FastApi dependency protection:\n@app.get('/admin/dashboard', dependencies=[Depends(require_admin_auth)])\nasync def dashboard():\n    return {'admin': True}\n```"
    ),
    "OPEN_REDIRECT": RemediationRule(
        category="OPEN_REDIRECT",
        explanation_template="Parameter '{parameter}' in {endpoint} forwards users to external target URLs without enforcing an explicit destination allowlist.",
        impact_template="Attackers can craft phishing campaigns using your trusted domain name to lure users to malicious credential-harvesting websites.",
        remediation_template="1. Restrict redirect targets to relative paths (e.g. starting with `/` but not `//`).\n2. Maintain an explicit allowlist of authorized external domains.\n3. Display an interstitial warning page if external navigation is mandatory.",
        prevention_guidance="```python\n# Secure Redirection Pattern:\nif not is_safe_relative_url(redirect_url):\n    redirect_url = '/dashboard'\nreturn RedirectResponse(url=redirect_url)\n```"
    ),
    "TYPE_CONFUSION": RemediationRule(
        category="TYPE_CONFUSION",
        explanation_template="Parameter '{parameter}' at {endpoint} produces unhandled application exceptions when supplied with unexpected data types.",
        impact_template="Can lead to denial of service, unhandled 500 crashes, or unexpected internal application logic branching.",
        remediation_template="1. Apply strict schema validation and type parsing at API boundaries.\n2. Use Pydantic or equivalent validation models to enforce numeric/string bounds.\n3. Gracefully return 400 Bad Request instead of throwing unhandled exceptions.",
        prevention_guidance="```python\n# Use strict Pydantic schemas:\nclass QueryModel(BaseModel):\n    category_id: int\n```"
    ),
    "INPUT_VALIDATION": RemediationRule(
        category="INPUT_VALIDATION",
        explanation_template="Parameter '{parameter}' at {endpoint} accepts unconstrained input characters.",
        impact_template="Exposes downstream business logic to injection, malformed parsing, or service instability.",
        remediation_template="1. Define an explicit allowlist regex for parameter '{parameter}'.\n2. Enforce minimum and maximum character length constraints.\n3. Reject unexpected input early in the request pipeline.",
        prevention_guidance="```python\n# Regex allowlist:\nif not re.match(r'^[a-zA-Z0-9_-]{1,64}$', parameter_val):\n    raise HTTPException(status_code=400, detail=\"Invalid parameter format\")\n```"
    )
}
