"""
backend/services/agent_service.py
Agent business logic: create, revoke, suspend, kill-switch.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.agent_auth import REDIS_REVOKED_PREFIX, hash_api_key
from backend.exceptions import AgentNotFoundError
from backend.storage.models.agent import Agent


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_agent(
    session: AsyncSession,
    name: str,
    tenant_id: str,
    permissions: list[str],
    max_refund_amount: float | None,
) -> tuple[Agent, str]:
    """
    Create a new agent.

    Returns (Agent, raw_api_key). The raw key is returned ONCE and never stored.
    """
    raw_key = secrets.token_urlsafe(32)
    key_hash = hash_api_key(raw_key)

    agent = Agent(
        id=uuid.uuid4(),
        name=name,
        tenant_id=uuid.UUID(tenant_id),
        api_key_hash=key_hash,
        status="active",
        permissions=permissions,
        max_refund_amount=max_refund_amount,
        created_at=_now(),
        updated_at=_now(),
    )
    session.add(agent)
    await session.flush()
    return agent, raw_key


async def get_agent(session: AsyncSession, agent_id: str) -> Agent:
    """Fetch an agent by UUID or raise AgentNotFoundError."""
    result = await session.execute(
        select(Agent).where(Agent.id == uuid.UUID(agent_id))
    )
    agent = result.scalar_one_or_none()
    if agent is None:
        raise AgentNotFoundError(f"Agent {agent_id!r} not found.")
    return agent


async def revoke_agent(
    session: AsyncSession,
    redis: aioredis.Redis,
    agent_id: str,
) -> Agent:
    """
    Revoke an agent permanently.
    Sets DB status to 'revoked' AND writes the Redis kill-switch key.
    """
    agent = await get_agent(session, agent_id)
    agent.status = "revoked"
    agent.updated_at = _now()
    await session.flush()

    # Write Redis kill-switch immediately so in-flight requests are also blocked.
    kill_key = f"{REDIS_REVOKED_PREFIX}{agent_id}"
    await redis.set(kill_key, "revoked")
    return agent


async def suspend_agent(session: AsyncSession, agent_id: str) -> Agent:
    """Temporarily suspend an agent (can be un-suspended, unlike revocation)."""
    agent = await get_agent(session, agent_id)
    agent.status = "suspended"
    agent.updated_at = _now()
    await session.flush()
    return agent


async def activate_agent(session: AsyncSession, agent_id: str) -> Agent:
    """Re-activate a suspended agent."""
    agent = await get_agent(session, agent_id)
    agent.status = "active"
    agent.updated_at = _now()
    await session.flush()
    return agent
