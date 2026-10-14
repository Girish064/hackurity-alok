"""
backend/api/capabilities.py
Capability issuance endpoint with adaptive policy integration.

POST /capabilities/issue  — request an action-bound capability through the
                            full authorization and adaptive policy process.

This endpoint wraps the gateway submission with:
  1. Adaptive policy evaluation (confidence score + risk classification)
  2. Standard response contract
  3. Baseline-aware enforcement
"""
from __future__ import annotations

import uuid
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.agent_auth import get_authenticated_agent
from backend.config import get_settings
from backend.dependencies import db_session, redis_client
from backend.exceptions import PolicyDeniedError, RateLimitExceededError
from backend.gateway.gateway_service import submit_action_after_approval
from backend.gateway.schemas import ActionSubmitRequest
from backend.storage.models.agent import Agent
from core.adaptive_policy import (
    AdaptivePolicyInput,
    PolicyOutcome,
    evaluate_adaptive_policy,
)
from core.baseline import get_active_baseline

router = APIRouter(prefix="/capabilities", tags=["Capabilities"])


class IssueCapabilityRequest(BaseModel):
    """Request body for POST /capabilities/issue."""
    action_type: str = Field(..., min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    request_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Client-generated UUID for idempotency (auto-generated if omitted)",
    )
    # Adaptive policy context
    agent_role: str = Field(
        "demo_agent",
        description="Agent role for adaptive policy evaluation",
    )
    context_reason: str = Field(
        "Standard request context",
        max_length=500,
        description="Human-readable context description",
    )
    context_valid: bool = Field(
        True,
        description="Whether upstream context validation passed",
    )

    model_config = {"populate_by_name": True}


@router.post("/issue", summary="Request an action-bound capability")
async def issue_capability(
    body: IssueCapabilityRequest,
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
    agent: Agent = Depends(get_authenticated_agent),
) -> dict[str, Any]:
    """
    Request an action-bound capability through the full authorization pipeline.

    This endpoint:
    1. Runs the adaptive policy engine (confidence score + risk level).
    2. If approved, invokes the deterministic policy engine.
    3. Issues a cryptographically signed capability on success.
    4. Returns the capability token and adaptive policy decision.

    Returns a standard AgentShield response envelope.
    """
    settings = get_settings()
    request_id = str(body.request_id)

    # ── Adaptive policy evaluation ────────────────────────────────────────
    # Extract numeric scope from parameters (e.g., amount for refunds)
    requested_scope = 0.0
    if "amount" in body.parameters:
        try:
            requested_scope = float(str(body.parameters["amount"]))
        except (ValueError, TypeError):
            pass

    # Get current baseline for scope limits
    active_baseline = get_active_baseline()

    adaptive_input = AdaptivePolicyInput(
        agent_id=str(agent.id),
        agent_role=body.agent_role,
        permitted_actions=list(agent.permissions or []),
        action_type=body.action_type,
        requested_scope=requested_scope,
        context_valid=body.context_valid,
        context_reason=body.context_reason,
        recent_failures=0,  # Could query DB for recent failures
        suspicious_activity=False,
    )

    adaptive_decision = evaluate_adaptive_policy(adaptive_input)

    # ── Adaptive policy hard denial ───────────────────────────────────────
    if adaptive_decision.outcome == PolicyOutcome.DENY:
        return {
            "status": "blocked",
            "code": "ADAPTIVE_POLICY_DENIED",
            "message": f"Adaptive policy denied request: {adaptive_decision.explanation}",
            "data": {
                "decision": "DENY",
                "adaptive_policy": adaptive_decision.as_dict(),
                "baseline": active_baseline.id.value,
            },
            "request_id": request_id,
        }

    # ── Route to gateway for deterministic policy + capability issuance ──
    gateway_request = ActionSubmitRequest(
        action_type=body.action_type,
        parameters=body.parameters,
        request_id=body.request_id,
    )

    try:
        gateway_result = await submit_action_after_approval(
            session, redis, agent, gateway_request
        )
    except PolicyDeniedError as exc:
        return {
            "status": "blocked",
            "code": "POLICY_DENIED",
            "message": str(exc.message),
            "data": {
                "decision": "DENY",
                "adaptive_policy": adaptive_decision.as_dict(),
                "baseline": active_baseline.id.value,
            },
            "request_id": request_id,
        }
    except RateLimitExceededError as exc:
        return {
            "status": "blocked",
            "code": "RATE_LIMIT_EXCEEDED",
            "message": str(exc.message),
            "data": {
                "adaptive_policy": adaptive_decision.as_dict(),
            },
            "request_id": request_id,
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "CAPABILITY_ISSUE_ERROR",
            "message": f"Capability issuance failed: {type(exc).__name__}",
            "data": {
                "adaptive_policy": adaptive_decision.as_dict(),
            },
            "request_id": request_id,
        }

    # ── Build success response ────────────────────────────────────────────
    gw_decision = gateway_result.get("decision", "UNKNOWN")

    if gw_decision == "ALLOW":
        return {
            "status": "success",
            "code": "CAPABILITY_ISSUED",
            "message": (
                f"Capability issued. Confidence: {adaptive_decision.confidence:.2f}, "
                f"Risk: {adaptive_decision.risk_level.value}, "
                f"TTL: {adaptive_decision.capability_ttl_seconds}s."
            ),
            "data": {
                "decision": "ALLOW",
                "capability_token": gateway_result.get("capability_token"),
                "action_digest": gateway_result.get("action_digest"),
                "expires_at": gateway_result.get("expires_at"),
                "adaptive_policy": adaptive_decision.as_dict(),
                "baseline": active_baseline.id.value,
            },
            "request_id": request_id,
        }

    if gw_decision == "REQUIRE_APPROVAL":
        return {
            "status": "success",
            "code": "APPROVAL_REQUIRED",
            "message": (
                f"Human approval required. "
                f"Adaptive confidence: {adaptive_decision.confidence:.2f}. "
                f"Reason: {adaptive_decision.approval_reason or 'Policy threshold.'}"
            ),
            "data": {
                "decision": "REQUIRE_APPROVAL",
                "approval_id": gateway_result.get("approval_id"),
                "adaptive_policy": adaptive_decision.as_dict(),
                "baseline": active_baseline.id.value,
            },
            "request_id": request_id,
        }

    return {
        "status": "blocked",
        "code": "POLICY_BLOCKED",
        "message": gateway_result.get("message", "Request blocked."),
        "data": {
            "decision": gw_decision,
            "adaptive_policy": adaptive_decision.as_dict(),
        },
        "request_id": request_id,
    }
