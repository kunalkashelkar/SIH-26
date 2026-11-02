import logging
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import AuditLog
from app.middleware.request_id import get_current_request_id

logger = logging.getLogger(__name__)

async def log_audit_event(
    db: AsyncSession,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    outcome: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
):
    """
    Persist an audit log entry for security-relevant user and administrative actions.
    Ensures secrets, credentials, and sensitive headers are excluded.
    """
    try:
        clean_details = dict(details or {})
        for key in list(clean_details.keys()):
            if any(k in key.lower() for k in ["password", "token", "secret", "auth", "cookie"]):
                clean_details[key] = "[REDACTED]"

        entry = AuditLog(
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id or get_current_request_id(),
            outcome=outcome,
            details=clean_details
        )
        db.add(entry)
        await db.commit()
    except Exception as e:
        logger.warning(f"Could not persist audit log: {e}")
