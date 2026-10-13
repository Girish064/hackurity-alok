"""
backend/api/gateway.py
Gateway endpoint — receives action submissions from AI agents.
"""
from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.agent_auth import get_authenticated_agent
from backend.dependencies import db_session, redis_client
from backend.gateway.gateway_service import submit_action, submit_action_after_approval
from backend.gateway.schemas import ActionSubmitRequest
from backend.storage.models.agent import Agent

router = APIRouter(prefix="/gateway", tags=["Gateway"])


@router.post(
    "/actions/submit",
    summary="Submit an action for authorization",
    status_code=200,
)
async def submit_action_endpoint(
    body: ActionSubmitRequest,
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
    agent: Agent = Depends(get_authenticated_agent),
) -> dict[str, Any]:
    """
    Submit an action for authorization.

    The gateway evaluates the deterministic policy and either:
    - Returns a signed capability token (ALLOW)
    - Returns an approval reference (REQUIRE_APPROVAL)
    - Raises a 403 error (DENY)

    The request_id is used as an idempotency key — re-submitting the same
    request_id returns the original decision without re-evaluation.

    When re-submitting after human approval (same request_id), the gateway
    checks the approval status and issues the capability if approved.
    """
    result = await submit_action_after_approval(session, redis, agent, body)
    return result
