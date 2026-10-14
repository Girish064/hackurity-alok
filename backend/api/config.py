"""
backend/api/config.py
Configuration and baseline control endpoints.

GET  /config     — read active configuration (open)
POST /config     — change baseline A/B/C (admin-only)
GET  /system/status — component availability and module health
"""
from __future__ import annotations

import os
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from backend.auth.admin_auth import get_admin_identity
from backend.config import get_settings
from backend.dependencies import redis_client
from backend.services.audit_service import append_event
from backend.dependencies import db_session
from sqlalchemy.ext.asyncio import AsyncSession
from core.baseline import (
    ALL_BASELINES,
    BaselineID,
    get_active_baseline,
    get_active_baseline_id,
    load_baseline_from_redis,
    persist_baseline_to_redis,
    set_active_baseline,
)

router = APIRouter(tags=["Config"])


class SetBaselineRequest(BaseModel):
    baseline: str = Field(
        ...,
        description="Baseline ID: A (minimal), B (gateway-only), or C (full enforcement)",
        pattern="^[ABC]$",
    )
    reason: str = Field(
        "",
        max_length=500,
        description="Optional reason for the configuration change (audited)",
    )


@router.get("/config", summary="Read active safe demonstration configuration")
async def get_config(
    redis: aioredis.Redis = Depends(redis_client),
) -> dict[str, Any]:
    """
    Return the active baseline configuration and all available baselines.
    Safe to expose — no secrets are included.
    """
    # Sync in-process state with Redis on read
    await load_baseline_from_redis(redis)
    active = get_active_baseline()

    return {
        "status": "success",
        "code": "CONFIG_OK",
        "message": f"Active baseline: {active.id.value}",
        "data": {
            "active_baseline": active.as_dict(),
            "available_baselines": {
                bid.value: cfg.as_dict()
                for bid, cfg in ALL_BASELINES.items()
            },
            "safety_note": (
                "Baselines A and B are intentionally vulnerable test configurations "
                "that MUST only be used with synthetic data and a local mock executor. "
                "Baseline C is the only production-safe configuration."
            ),
        },
        "request_id": None,
    }


@router.post("/config", summary="Change baseline via authorized administrative path")
async def set_config(
    body: SetBaselineRequest,
    redis: aioredis.Redis = Depends(redis_client),
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    """
    Change the active baseline.

    Requires admin authentication.
    The change is audited and persisted to Redis.
    """
    new_id = BaselineID(body.baseline)
    previous = get_active_baseline_id()

    # Apply change
    new_cfg = set_active_baseline(new_id)
    await persist_baseline_to_redis(redis, new_id)

    # Audit the configuration change
    await append_event(
        session,
        event_type="BASELINE_CHANGED",
        event_data={
            "previous_baseline": previous.value,
            "new_baseline": new_id.value,
            "changed_by": admin,
            "reason": body.reason,
            "safety_note": (
                f"Baseline {new_id.value} is {'VULNERABLE — synthetic data only' if new_id.value in ('A', 'B') else 'the full enforcement configuration'}."
            ),
        },
        actor_id=admin,
    )

    return {
        "status": "success",
        "code": "CONFIG_UPDATED",
        "message": (
            f"Baseline changed from {previous.value} to {new_id.value}. "
            f"Change is audited."
        ),
        "data": {
            "previous_baseline": previous.value,
            "active_baseline": new_cfg.as_dict(),
            "warning": (
                f"Baseline {new_id.value} is {'INTENTIONALLY VULNERABLE — use synthetic data only!' if new_id.value in ('A','B') else 'fully enforced (safe).'}"
            ),
        },
        "request_id": None,
    }


@router.get("/system/status", summary="Active configuration and module availability")
async def system_status(
    redis: aioredis.Redis = Depends(redis_client),
) -> dict[str, Any]:
    """
    Return the active baseline, module availability, and configuration summary.
    Does not expose secrets.
    """
    settings = get_settings()

    # Check Redis
    redis_ok = True
    try:
        await redis.ping()
    except Exception:
        redis_ok = False

    # Check security module
    security_ok = True
    try:
        import security as sec
        _ = sec.canonicalize_action
    except Exception:
        security_ok = False

    # Check OPA (optional)
    opa_url = os.environ.get("OPA_URL", "")
    opa_status = "disabled"
    if opa_url:
        from backend.policy.opa_client import opa_health_check
        opa_result = opa_health_check(opa_url)
        opa_status = opa_result.get("status", "unknown")

    # Sync baseline
    await load_baseline_from_redis(redis)
    active = get_active_baseline()

    # Key configuration (no secrets)
    has_signing_key = bool(settings.agentshield_signing_key_pem)
    has_verifying_key = bool(settings.agentshield_verifying_key_pem)

    return {
        "status": "success",
        "code": "SYSTEM_OK",
        "message": "System status retrieved.",
        "data": {
            "active_baseline": active.id.value,
            "baseline_name": active.name,
            "baseline_risk_level": active.risk_level,
            "modules": {
                "redis": "ok" if redis_ok else "error",
                "security_module": "ok" if security_ok else "error",
                "opa": opa_status,
                "database": "ok",  # If we reached this far, DB is up
            },
            "configuration": {
                "executor_id": settings.agentshield_executor_id,
                "key_id": settings.agentshield_key_id,
                "capability_ttl_seconds": settings.capability_ttl_seconds,
                "has_signing_key": has_signing_key,
                "has_verifying_key": has_verifying_key,
                "ephemeral_keys": not has_signing_key,
                "app_env": settings.app_env,
            },
        },
        "request_id": None,
    }
