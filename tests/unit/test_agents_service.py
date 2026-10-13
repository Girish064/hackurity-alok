"""
tests/unit/test_agents_service.py
Unit tests for agent lifecycle management service.
"""
from __future__ import annotations

import uuid

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio

from backend.auth.agent_auth import REDIS_REVOKED_PREFIX
from backend.exceptions import AgentNotFoundError
from backend.services.agent_service import (
    activate_agent,
    create_agent,
    get_agent,
    revoke_agent,
    suspend_agent,
)


@pytest_asyncio.fixture
async def redis():
    r = fakeredis.FakeRedis()
    yield r
    await r.aclose()


class TestAgentService:
    async def test_create_and_get_agent(self, sqlite_session):
        tenant_id = str(uuid.uuid4())
        agent, raw_key = await create_agent(
            sqlite_session,
            name="service-test-agent",
            tenant_id=tenant_id,
            permissions=["ISSUE_REFUND"],
            max_refund_amount=1000.0,
        )
        assert agent.name == "service-test-agent"
        assert raw_key is not None
        assert len(raw_key) > 20

        fetched = await get_agent(sqlite_session, str(agent.id))
        assert fetched.id == agent.id
        assert fetched.status == "active"

    async def test_suspend_and_activate_agent(self, sqlite_session):
        tenant_id = str(uuid.uuid4())
        agent, _ = await create_agent(
            sqlite_session,
            name="suspendable-agent",
            tenant_id=tenant_id,
            permissions=[],
            max_refund_amount=None,
        )
        agent_id = str(agent.id)

        suspended = await suspend_agent(sqlite_session, agent_id)
        assert suspended.status == "suspended"

        activated = await activate_agent(sqlite_session, agent_id)
        assert activated.status == "active"

    async def test_revoke_agent_sets_kill_switch(self, sqlite_session, redis):
        tenant_id = str(uuid.uuid4())
        agent, _ = await create_agent(
            sqlite_session,
            name="revocable-agent",
            tenant_id=tenant_id,
            permissions=[],
            max_refund_amount=None,
        )
        agent_id = str(agent.id)

        revoked = await revoke_agent(sqlite_session, redis, agent_id)
        assert revoked.status == "revoked"

        # Verify Redis kill-switch key was set
        kill_key = f"{REDIS_REVOKED_PREFIX}{agent_id}"
        assert await redis.exists(kill_key)

    async def test_get_nonexistent_agent_raises(self, sqlite_session):
        with pytest.raises(AgentNotFoundError):
            await get_agent(sqlite_session, str(uuid.uuid4()))
