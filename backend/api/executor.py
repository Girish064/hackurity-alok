"""
backend/api/executor.py
Protected executor endpoint.
"""
from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dependencies import db_session, redis_client
from backend.executor.executor_service import execute_action
from backend.executor.schemas import ExecuteRequest, ExecuteResponse

router = APIRouter(prefix="/executor", tags=["Executor"])


@router.post(
    "/execute",
    response_model=ExecuteResponse,
    summary="Execute an authorized action",
)
async def execute_endpoint(
    body: ExecuteRequest,
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
) -> ExecuteResponse:
    """
    Execute a previously authorized action using a signed capability token.

    The executor independently verifies:
    - The Ed25519 signature of the capability.
    - That the action parameters match the capability's action digest.
    - That the principal and tenant match.
    - That the capability has not expired.
    - That the agent is not revoked (Redis kill-switch).
    - That the capability has not been used before (replay prevention).

    The tool only runs AFTER all checks pass.
    This endpoint intentionally does NOT require agent authentication:
    the capability token is the authorization evidence, and the executor
    verifies it independently.
    """
    return await execute_action(session, redis, body)
