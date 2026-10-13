"""
backend/api/health.py
Health check endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import redis.asyncio as aioredis
from backend.dependencies import db_session, redis_client

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Health check")
async def health(
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
) -> dict:
    """
    Returns service health status.
    Checks DB connectivity and Redis connectivity.
    """
    db_status = "ok"
    redis_status = "ok"

    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {exc}"

    try:
        await redis.ping()
    except Exception as exc:
        redis_status = f"error: {exc}"

    overall = "ok" if db_status == "ok" and redis_status == "ok" else "degraded"
    return {"status": overall, "db": db_status, "redis": redis_status}
