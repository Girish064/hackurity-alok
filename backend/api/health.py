"""
backend/api/health.py
Health check endpoint — standard AgentShield V3 response contract.
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import redis.asyncio as aioredis
from backend.dependencies import db_session, redis_client
from core.baseline import get_active_baseline

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Service health and dependency status")
async def health(
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
) -> dict[str, Any]:
    """
    Returns service health and dependency status.
    Checks: database, Redis, security module, OPA (if configured).
    """
    db_status = "ok"
    redis_status = "ok"

    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {type(exc).__name__}"

    try:
        await redis.ping()
    except Exception as exc:
        redis_status = f"error: {type(exc).__name__}"

    # Security module check
    sec_status = "ok"
    try:
        import security as sec
        _ = sec.canonicalize_action
    except Exception as exc:
        sec_status = f"error: {type(exc).__name__}"

    # OPA (optional)
    opa_url = os.environ.get("OPA_URL", "")
    opa_status = "disabled"
    if opa_url:
        from backend.policy.opa_client import opa_health_check
        opa_result = opa_health_check(opa_url)
        opa_status = opa_result.get("status", "unknown")

    all_critical_ok = db_status == "ok" and redis_status == "ok" and sec_status == "ok"
    overall = "ok" if all_critical_ok else "degraded"

    active_baseline = get_active_baseline()

    return {
        "status": "success" if all_critical_ok else "error",
        "code": "HEALTH_OK" if all_critical_ok else "HEALTH_DEGRADED",
        "message": f"Service is {overall}.",
        "data": {
            "overall": overall,
            "components": {
                "database": db_status,
                "redis": redis_status,
                "security_module": sec_status,
                "opa": opa_status,
            },
            "active_baseline": active_baseline.id.value,
            "baseline_name": active_baseline.name,
        },
        "request_id": None,
    }
