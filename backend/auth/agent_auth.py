"""
backend/auth/agent_auth.py
Agent authentication: API key verification and identity resolution.

Design:
  - Agents are registered with a raw API key; only the SHA-256 hash is stored.
  - Requests carry the API key in the Authorization: Bearer header.
  - The key is hashed on every request and looked up in the agents table.
  - If the agent is revoked/suspended, authentication is rejected immediately.
  - The Redis kill-switch is checked in addition to the DB status.
"""
from __future__ import annotations

import hashlib

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dependencies import db_session, redis_client
from backend.exceptions import (
    AgentNotFoundError,
    AgentRevokedError,
    AgentSuspendedError,
    AuthenticationError,
)
from backend.storage.models.agent import Agent

_bearer = HTTPBearer(auto_error=False)

REDIS_REVOKED_PREFIX = "agentshield:revoked:"


def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of the raw API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


async def get_authenticated_agent(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
) -> Agent:
    """
    FastAPI dependency that resolves the authenticated Agent from the Bearer token.
    Raises an appropriate AgentShieldError on any failure.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(
            "Missing Authorization header. Provide: Authorization: Bearer <api_key>"
        )

    raw_key = credentials.credentials
    key_hash = hash_api_key(raw_key)

    # DB lookup
    result = await session.execute(
        select(Agent).where(Agent.api_key_hash == key_hash)
    )
    agent: Agent | None = result.scalar_one_or_none()

    if agent is None:
        raise AgentNotFoundError("Invalid API key — agent not found.")

    # DB-level status check
    if agent.status == "revoked":
        raise AgentRevokedError(
            f"Agent {agent.id} has been revoked and cannot perform actions."
        )
    if agent.status == "suspended":
        raise AgentSuspendedError(
            f"Agent {agent.id} is currently suspended."
        )

    # Redis kill-switch (checked even if DB says active, for fast propagation)
    kill_key = f"{REDIS_REVOKED_PREFIX}{agent.id}"
    is_killed = await redis.exists(kill_key)
    if is_killed:
        raise AgentRevokedError(
            f"Agent {agent.id} is subject to the kill switch."
        )

    return agent
