import httpx
import asyncio
import logging
import urllib.parse
import ipaddress

logger = logging.getLogger(__name__)

CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",
}

def is_safe_target_url(url: str, allow_localhost: bool = True) -> bool:
    """Validate target URL against SSRF and cloud metadata endpoints."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ["http", "https"]:
            return False

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        if hostname in CLOUD_METADATA_HOSTS:
            return False

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_link_local or ip == ipaddress.ip_address("169.254.169.254"):
                return False
            if ip.is_loopback:
                return allow_localhost
            if ip.is_private and not allow_localhost:
                return False
        except ValueError:
            if hostname in ["localhost", "127.0.0.1", "::1"]:
                return allow_localhost

        return True
    except Exception:
        return False

class ResilientHttpClient:
    def __init__(self, max_requests: int = 10000, concurrency: int = 10, timeout: int = 10, rate_limit_ms: int = 0, allow_localhost: bool = True):
        self.max_requests = max_requests
        self.request_count = 0
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limit_sec = rate_limit_ms / 1000.0
        self.allow_localhost = allow_localhost
        
        # Configure httpx limits
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), limits=limits, follow_redirects=True)

    async def get(self, url: str, **kwargs):
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs):
        if not is_safe_target_url(url, allow_localhost=self.allow_localhost):
            logger.warning(f"Blocked unsafe SSRF request to URL: {url}")
            return None

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
