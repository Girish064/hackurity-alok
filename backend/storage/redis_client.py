"""
backend/storage/redis_client.py
Async Redis connection pool wrapper.
"""
from __future__ import annotations

import redis.asyncio as aioredis

_redis_client: aioredis.Redis | None = None


def init_redis(redis_url: str) -> None:
    """Initialise the Redis connection pool (called once at application startup)."""
    global _redis_client
    _redis_client = aioredis.from_url(
        redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20,
    )


async def get_redis() -> aioredis.Redis:
    """FastAPI dependency that returns the shared Redis client."""
    if _redis_client is None:
        raise RuntimeError("Redis client not initialised. Call init_redis() first.")
    return _redis_client


async def close_redis() -> None:
    """Close the Redis connection pool on application shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
