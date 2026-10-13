"""
backend/gateway/rate_limiter.py
Redis-backed sliding-window rate limiter.

Uses a fixed-window approach per minute bucket (simple and predictable).
Key: agentshield:ratelimit:{agent_id}:{minute_bucket}
TTL: 60 seconds
"""
from __future__ import annotations

import time

import redis.asyncio as aioredis

from backend.config import get_settings
from backend.exceptions import RateLimitExceededError

RATE_LIMIT_PREFIX = "agentshield:ratelimit:"


async def check_rate_limit(
    redis: aioredis.Redis,
    agent_id: str,
) -> None:
    """
    Increment the per-agent per-minute counter and raise RateLimitExceededError
    if the limit is exceeded.

    This is intentionally simple: fixed-window per minute.
    """
    settings = get_settings()
    limit = settings.rate_limit_per_minute
    minute_bucket = int(time.time() // 60)
    key = f"{RATE_LIMIT_PREFIX}{agent_id}:{minute_bucket}"

    # INCR + EXPIRE in a pipeline (atomic enough for rate limiting)
    async with redis.pipeline(transaction=False) as pipe:
        pipe.incr(key)
        pipe.expire(key, 60)
        results = await pipe.execute()

    count = results[0]
    if count > limit:
        raise RateLimitExceededError(
            f"Agent {agent_id!r} exceeded the rate limit of {limit} "
            f"requests per minute. Current count: {count}."
        )
