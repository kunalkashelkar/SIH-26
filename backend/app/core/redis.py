import logging
from typing import Optional, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

_redis_pool: Optional[Any] = None

def get_redis_pool() -> Optional[Any]:
    """Get or create singleton Redis connection pool if redis is installed."""
    global _redis_pool
    if aioredis is None:
        return None
    if _redis_pool is None and getattr(settings, "REDIS_URL", None):
        try:
            _redis_pool = aioredis.ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=20,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
        except Exception as e:
            logger.debug(f"Could not initialize Redis connection pool: {e}")
            _redis_pool = None
    return _redis_pool

async def get_redis_client() -> Optional[Any]:
    """Retrieve async Redis client or None if Redis is unreachable or not installed."""
    if aioredis is None:
        return None
    pool = get_redis_pool()
    if pool is None:
        return None
    try:
        client = aioredis.Redis(connection_pool=pool)
        return client
    except Exception as e:
        logger.debug(f"Redis client acquisition error: {e}")
        return None

async def check_redis_health() -> bool:
    """Health check for Redis connectivity."""
    try:
        client = await get_redis_client()
        if client:
            res = await client.ping()
            await client.close()
            return res is True
    except Exception as e:
        logger.debug(f"Redis health check failed: {e}")
    return False

async def close_redis():
    """Cleanly disconnect Redis connection pool on app shutdown."""
    global _redis_pool
    if _redis_pool:
        try:
            await _redis_pool.disconnect()
        except Exception as e:
            logger.debug(f"Error disconnecting Redis pool: {e}")
        _redis_pool = None
