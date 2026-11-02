import httpx
import asyncio
import logging

logger = logging.getLogger(__name__)

class ResilientHttpClient:
    def __init__(self, max_requests: int = 10000, concurrency: int = 10, timeout: int = 10, rate_limit_ms: int = 0):
        self.max_requests = max_requests
        self.request_count = 0
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_sec = rate_limit_ms / 1000.0
        
        # Configure httpx limits
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), limits=limits, follow_redirects=True)

    async def get(self, url: str, **kwargs):
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs):
        if self.request_count >= self.max_requests:
            logger.warning(f"Max requests ({self.max_requests}) reached. Blocking further requests.")
            raise Exception("Max request limit reached")

        async with self.semaphore:
            self.request_count += 1
            if self.rate_limit_sec > 0:
                await asyncio.sleep(self.rate_limit_sec)
                
            try:
                response = await self.client.request(method, url, **kwargs)
                return response
            except httpx.RequestError as e:
                logger.error(f"HTTP Request failed: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error during HTTP request: {e}")
                return None

    async def close(self):
        await self.client.aclose()
