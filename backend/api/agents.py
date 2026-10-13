"""
backend/api/agents.py
Agent registration and management endpoints.
"""
from __future__ import annotations

import uuid
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.admin_auth import get_admin_identity
from backend.dependencies import db_session, redis_client
from backend.services.agent_service import (
    activate_agent,
    create_agent,
    get_agent,
    revoke_agent,
    suspend_agent,
)

router = APIRouter(prefix="/agents", tags=["Agents"])


# ── Schemas ────────────────────────────────────────────────────────────────


class CreateAgentRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    tenant_id: str = Field(..., description="UUID string")
    permissions: list[str] = Field(default_factory=list)
    max_refund_amount: float | None = Field(None, ge=0)


class AgentResponse(BaseModel):
    id: str
    name: str
    tenant_id: str
    status: str
    permissions: list[str]
    max_refund_amount: float | None
    created_at: str


class AuthRequest(BaseModel):
    api_key: str


class AuthResponse(BaseModel):
    agent_id: str
    name: str
    status: str
    # Note: the bearer token for subsequent calls IS the raw API key.
    # In production this would issue a JWT. For demo, returning agent info.
    message: str


# ── Routes ─────────────────────────────────────────────────────────────────


@router.post("", status_code=201, summary="Register a new agent")
async def register_agent(
    body: CreateAgentRequest,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    """
    Register a new AI agent.
    Returns the raw API key ONCE — it is not stored and cannot be retrieved again.
    """
    try:
        uuid.UUID(body.tenant_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="tenant_id must be a valid UUID")

    agent, raw_key = await create_agent(
        session=session,
        name=body.name,
        tenant_id=body.tenant_id,
        permissions=body.permissions,
        max_refund_amount=body.max_refund_amount,
    )
    return {
        "id": str(agent.id),
        "name": agent.name,
        "tenant_id": str(agent.tenant_id),
        "status": agent.status,
        "permissions": agent.permissions,
        "max_refund_amount": float(agent.max_refund_amount) if agent.max_refund_amount else None,
        "api_key": raw_key,  # Returned ONCE only
        "created_at": agent.created_at.isoformat(),
        "message": (
            "Agent registered. Store the api_key securely — "
            "it cannot be retrieved again."
        ),
    }


@router.get("/{agent_id}", summary="Get agent details")
async def get_agent_details(
    agent_id: str,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    agent = await get_agent(session, agent_id)
    return {
        "id": str(agent.id),
        "name": agent.name,
        "tenant_id": str(agent.tenant_id),
        "status": agent.status,
        "permissions": agent.permissions,
        "max_refund_amount": float(agent.max_refund_amount) if agent.max_refund_amount else None,
        "created_at": agent.created_at.isoformat(),
        "updated_at": agent.updated_at.isoformat(),
    }


@router.patch("/{agent_id}/revoke", summary="Permanently revoke an agent")
async def revoke_agent_endpoint(
    agent_id: str,
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    """
    Revoke an agent permanently.
    Sets DB status to 'revoked' and writes the Redis kill-switch key.
    """
    agent = await revoke_agent(session, redis, agent_id)
    return {
        "id": str(agent.id),
        "status": agent.status,
        "message": f"Agent {agent_id!r} has been permanently revoked.",
    }


@router.patch("/{agent_id}/suspend", summary="Temporarily suspend an agent")
async def suspend_agent_endpoint(
    agent_id: str,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    agent = await suspend_agent(session, agent_id)
    return {"id": str(agent.id), "status": agent.status}


@router.patch("/{agent_id}/activate", summary="Re-activate a suspended agent")
async def activate_agent_endpoint(
    agent_id: str,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    agent = await activate_agent(session, agent_id)
    return {"id": str(agent.id), "status": agent.status}
