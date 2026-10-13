"""
tests/unit/test_replay_guard.py
Unit tests for atomic capability consumption.

Uses fakeredis to simulate concurrent access without a real Redis server.
"""
from __future__ import annotations

import asyncio

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio

from backend.executor.replay_guard import consume_capability, is_consumed
from backend.exceptions import CapabilityConsumedError


@pytest_asyncio.fixture
async def redis():
    r = fakeredis.FakeRedis()
    yield r
    await r.aclose()


class TestReplayGuard:
    async def test_first_consumption_succeeds(self, redis):
        await consume_capability(redis, "cap-001", 3600)
        assert await is_consumed(redis, "cap-001")

    async def test_second_consumption_raises(self, redis):
        await consume_capability(redis, "cap-002", 3600)
        with pytest.raises(CapabilityConsumedError):
            await consume_capability(redis, "cap-002", 3600)

    async def test_different_capabilities_independent(self, redis):
        await consume_capability(redis, "cap-A", 3600)
        # cap-B should still be consumable
        await consume_capability(redis, "cap-B", 3600)

    async def test_concurrent_replay_only_one_succeeds(self, redis):
        """
        Simulate two concurrent attempts to consume the same capability.
        Exactly one must succeed; the other must raise CapabilityConsumedError.
        """
        cap_id = "cap-concurrent"
        results = []

        async def try_consume():
            try:
                await consume_capability(redis, cap_id, 3600)
                results.append("success")
            except CapabilityConsumedError:
                results.append("rejected")

        await asyncio.gather(try_consume(), try_consume())

        assert results.count("success") == 1
        assert results.count("rejected") == 1

    async def test_is_consumed_false_before_consumption(self, redis):
        assert not await is_consumed(redis, "cap-never")
