import logging
from typing import Optional
from app.scanner.http_client import ResilientHttpClient
from app.models.models import Endpoint

logger = logging.getLogger(__name__)

class BaselineResponse:
    def __init__(self, endpoint_id: str, status_code: int, content_length: int, content_type: str, body_snippet: str):
        self.endpoint_id = endpoint_id
        self.status_code = status_code
        self.content_length = content_length
        self.content_type = content_type
        self.body_snippet = body_snippet

class BaselineCollector:
    def __init__(self, client: ResilientHttpClient):
        self.client = client
        self._cache: dict[str, BaselineResponse] = {}

    async def get_baseline(self, endpoint: Endpoint) -> Optional[BaselineResponse]:
        """
        Fetches or retrieves cached benign baseline response for an endpoint.
        """
        if endpoint.id in self._cache:
            return self._cache[endpoint.id]

        method = (endpoint.method or "GET").upper()
        url = endpoint.url

        try:
            resp = await self.client._request(method=method, url=url)
            if resp:
                body = resp.text if hasattr(resp, "text") else ""
                content_type = resp.headers.get("content-type", "")
                base = BaselineResponse(
                    endpoint_id=endpoint.id,
                    status_code=resp.status_code,
                    content_length=len(body),
                    content_type=content_type,
                    body_snippet=body[:300]
                )
                self._cache[endpoint.id] = base
                return base
        except Exception as e:
            logger.warning(f"Failed to capture baseline for {endpoint.url}: {e}")

        # Fallback baseline from endpoint record
        fallback = BaselineResponse(
            endpoint_id=endpoint.id,
            status_code=endpoint.status_code or 200,
            content_length=0,
            content_type=endpoint.content_type or "text/html",
            body_snippet=""
        )
        self._cache[endpoint.id] = fallback
        return fallback
