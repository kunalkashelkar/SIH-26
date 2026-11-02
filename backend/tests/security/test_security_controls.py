import pytest
from app.core.security import require_roles
from app.core.exceptions import ForbiddenException
from app.scanner.http_client import is_safe_target_url

@pytest.mark.asyncio
async def test_rbac_role_enforcement():
    admin_checker = require_roles(["ADMIN"])
    user_checker = require_roles(["ANALYST"])

    # Admin user passes admin checker
    admin_user = {"id": "u-1", "email": "admin@example.com", "role": "ADMIN"}
    res = await admin_checker(user=admin_user)
    assert res["role"] == "ADMIN"

    # Regular user fails admin checker
    regular_user = {"id": "u-2", "email": "user@example.com", "role": "USER"}
    with pytest.raises(ForbiddenException):
        await admin_checker(user=regular_user)

    # Admin also passes analyst checker due to privilege hierarchy
    res_admin = await user_checker(user=admin_user)
    assert res_admin["role"] == "ADMIN"

def test_ssrf_egress_safety_validation():
    # Loopback targets blocked when not configured
    assert not is_safe_target_url("http://127.0.0.1:8000/admin", allow_localhost=False)
    assert not is_safe_target_url("http://localhost:5432", allow_localhost=False)

    # Cloud metadata blocked unconditionally
    assert not is_safe_target_url("http://169.254.169.254/latest/meta-data/")
    assert not is_safe_target_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not is_safe_target_url("http://169.254.169.254/latest/meta-data/", allow_localhost=True)

    # Allowed external HTTP/HTTPS targets
    assert is_safe_target_url("https://juice-shop.herokuapp.com")
    assert is_safe_target_url("http://example.com")
