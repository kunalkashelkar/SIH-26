import time
import logging
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.core.redis import get_redis_client
from app.core.exceptions import format_error_response

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding window rate limiting middleware.
    Uses Redis when available, falling back to an in-memory window per IP.
    """
    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # In-memory fallback: ip -> list of timestamps
        self._memory_buckets: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Exclude static assets or health checks from rate limiting
        path = request.url.path
        if path in ["/api/health", "/api/v1/health", "/docs", "/openapi.json"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        allowed = True
        retry_after = self.window_seconds

        # 1. Try Redis distributed rate limiting
        try:
            redis_client = await get_redis_client()
            if redis_client:
                key = f"rate_limit:{client_ip}:{int(now // self.window_seconds)}"
                current_count = await redis_client.incr(key)
                if current_count == 1:
                    await redis_client.expire(key, self.window_seconds)
                if current_count > self.max_requests:
                    allowed = False
                    ttl = await redis_client.ttl(key)
                    retry_after = max(ttl, 1)
                await redis_client.close()
            else:
                # 2. In-memory fallback
                timestamps = self._memory_buckets[client_ip]
                cutoff = now - self.window_seconds
                self._memory_buckets[client_ip] = [t for t in timestamps if t > cutoff]
                if len(self._memory_buckets[client_ip]) >= self.max_requests:
                    allowed = False
                else:
                    self._memory_buckets[client_ip].append(now)
        except Exception as e:
            logger.debug(f"Rate limiting check error: {e}")
            allowed = True  # Fail open on unexpected error

        if not allowed:
            req_id = getattr(request.state, "request_id", "")
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content=format_error_response(
                    code="RATE_LIMIT_EXCEEDED",
                    message=f"Rate limit of {self.max_requests} requests per {self.window_seconds}s exceeded.",
                    request_id=req_id,
                    details={"retry_after_seconds": retry_after}
                )
            )

        return await call_next(request)
