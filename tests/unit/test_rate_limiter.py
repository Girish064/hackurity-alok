"""
tests/unit/test_rate_limiter.py
Unit tests for the Redis rate limiter.
"""
from __future__ import annotations

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio

from backend.config import get_settings
from backend.exceptions import RateLimitExceededError
from backend.gateway.rate_limiter import check_rate_limit


@pytest_asyncio.fixture
async def redis():
    r = fakeredis.FakeRedis()
    yield r
    await r.aclose()


class TestRateLimiter:
    async def test_requests_within_limit_pass(self, redis):
        for _ in range(5):
            await check_rate_limit(redis, "agent-rl-01")

    async def test_requests_exceeding_limit_raise(self, redis):
        settings = get_settings()
        limit = settings.rate_limit_per_minute

        for _ in range(limit):
            await check_rate_limit(redis, "agent-rl-02")

        with pytest.raises(RateLimitExceededError):
            await check_rate_limit(redis, "agent-rl-02")
