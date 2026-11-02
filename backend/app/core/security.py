import json
import base64
import logging
from typing import Optional, Dict, Any
from fastapi import Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)
security_bearer = HTTPBearer(auto_error=False)

def decode_unverified_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT payload to extract user claims without requiring network call."""
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1]
            padding = "=" * (4 - len(payload_b64) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
            return json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        logger.debug(f"Could not parse token: {e}")
    return None

async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> Optional[Dict[str, Any]]:
    """
    Extract authenticated user context from Better Auth Bearer token or cookie.
    Returns user dict with 'id', 'email', 'name' if present, or None.
    """
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        # Check authorization header directly
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            # Check better-auth session cookie
            token = request.cookies.get("better-auth.session_token")

    if token:
        claims = decode_unverified_jwt(token)
        if claims:
            user_id = claims.get("sub") or claims.get("id") or claims.get("userId")
            email = claims.get("email")
            return {"id": user_id, "email": email, "claims": claims}
    
    return None
