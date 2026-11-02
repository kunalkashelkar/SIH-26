import uuid
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")

def get_current_request_id() -> str:
    """Retrieve current request ID from context var or generate a new one."""
    req_id = request_id_ctx.get()
    return req_id if req_id else str(uuid.uuid4())

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attaches a unique X-Request-ID to every request context
    and injects it into response headers.
    """
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_ctx.set(req_id)
        request.state.request_id = req_id

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_ctx.reset(token)
