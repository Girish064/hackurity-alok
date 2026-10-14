"""
backend/api/actions.py
Action request query and submission endpoints.

GET  /actions              — list recent action requests
GET  /actions/{request_id} — single action request
POST /actions/submit       — submit an action for execution (wraps gateway + executor)
"""
from __future__ import annotations

import uuid
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.agent_auth import get_authenticated_agent, get_optional_agent
from backend.dependencies import db_session, redis_client
from backend.exceptions import (
    AgentShieldError,
    AuthenticationError,
    PolicyDeniedError,
    RateLimitExceededError,
)
from backend.executor.executor_service import execute_action
from backend.executor.schemas import ExecuteRequest
from backend.gateway.gateway_service import submit_action_after_approval
from backend.gateway.schemas import ActionSubmitRequest
from backend.storage.models.agent import Agent
from backend.storage.models.action_request import ActionRequest

router = APIRouter(prefix="/actions", tags=["Actions"])


# ── Schemas ────────────────────────────────────────────────────────────────


class SubmitActionRequest(BaseModel):
    """Body for POST /actions/submit."""
    action_type: str = Field(..., min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    capability_token: str | None = Field(
        None,
        description="Signed capability token for protected execution. If omitted, submits for capability issuance.",
    )
    request_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Client-generated UUID for idempotency",
    )


# ── Helpers ────────────────────────────────────────────────────────────────


def _ar_to_dict(ar: ActionRequest) -> dict[str, Any]:
    return {
        "request_id": str(ar.id),
        "agent_id": str(ar.agent_id),
        "tenant_id": str(ar.tenant_id),
        "action_type": ar.action_type,
        "parameters": ar.parameters,
        "action_digest": ar.action_digest,
        "policy_decision": ar.policy_decision,
        "status": ar.status,
        "capability_id": str(ar.capability_id) if ar.capability_id else None,
        "expires_at": ar.expires_at.isoformat() if ar.expires_at else None,
        "submitted_at": ar.submitted_at.isoformat() if ar.submitted_at else None,
    }


# ── Routes ─────────────────────────────────────────────────────────────────


@router.post("/submit", summary="Submit an action and capability for protected execution")
async def submit_action_endpoint(
    body: SubmitActionRequest,
    session: AsyncSession = Depends(db_session),
    redis: aioredis.Redis = Depends(redis_client),
    agent: Agent | None = Depends(get_optional_agent),
) -> dict[str, Any]:
    """
    Submit an action and capability for protected execution.

    If capability_token is provided:
        Executes the action through the independent executor boundary (re-canonicalizing,
        verifying signatures, checking single-use consumption, and generating signed receipts).

    If capability_token is omitted:
        Submits the action to the gateway policy engine for authorization and capability issuance.
    """
    request_id = str(body.request_id)

    # ── Path A: Direct protected execution with capability token ──────────
    if body.capability_token:
        exec_req = ExecuteRequest(
            action_type=body.action_type,
            parameters=body.parameters,
            capability_token=body.capability_token,
        )
        try:
            exec_resp = await execute_action(session, redis, exec_req)
            return {
                "status": "success",
                "code": "ACTION_EXECUTED",
                "message": f"Action {body.action_type} executed successfully.",
                "data": {
                    "execution_id": exec_resp.execution_id,
                    "outcome": exec_resp.outcome,
                    "outcome_data": exec_resp.outcome_data,
                    "receipt_token": exec_resp.receipt_token,
                    "executed_at": exec_resp.executed_at,
                },
                "request_id": request_id,
            }
        except AgentShieldError as exc:
            return {
                "status": "blocked",
                "code": exc.error_code,
                "message": exc.message,
                "data": {
                    "decision": "BLOCKED",
                    "error_code": exc.error_code,
                },
                "request_id": request_id,
            }
        except Exception as exc:
            return {
                "status": "error",
                "code": "EXECUTION_ERROR",
                "message": f"Execution failed: {type(exc).__name__}",
                "data": {},
                "request_id": request_id,
            }

    # ── Path B: Capability issuance request (requires authenticated agent) ─
    if agent is None:
        raise AuthenticationError(
            "Missing Authorization header. Provide: Authorization: Bearer <api_key>"
        )

    gateway_request = ActionSubmitRequest(
        action_type=body.action_type,
        parameters=body.parameters,
        request_id=body.request_id,
    )

    try:
        result = await submit_action_after_approval(session, redis, agent, gateway_request)
    except PolicyDeniedError as exc:
        return {
            "status": "blocked",
            "code": "POLICY_DENIED",
            "message": exc.message,
            "data": {"decision": "DENY"},
            "request_id": request_id,
        }
    except RateLimitExceededError as exc:
        return {
            "status": "blocked",
            "code": "RATE_LIMIT_EXCEEDED",
            "message": exc.message,
            "data": {},
            "request_id": request_id,
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "SUBMIT_ERROR",
            "message": f"Action submission failed: {type(exc).__name__}",
            "data": {},
            "request_id": request_id,
        }

    decision = result.get("decision", "UNKNOWN")
    if decision == "ALLOW":
        return {
            "status": "success",
            "code": "CAPABILITY_ISSUED",
            "message": "Capability issued. Submit to /executor/execute to run.",
            "data": result,
            "request_id": request_id,
        }
    elif decision == "REQUIRE_APPROVAL":
        return {
            "status": "success",
            "code": "APPROVAL_REQUIRED",
            "message": "Human approval required before capability can be issued.",
            "data": result,
            "request_id": request_id,
        }
    else:
        return {
            "status": "blocked",
            "code": "POLICY_BLOCKED",
            "message": result.get("message", "Request blocked."),
            "data": result,
            "request_id": request_id,
        }


@router.get("", summary="List recent action requests")
async def list_actions(
    agent_id: str | None = Query(None, description="Filter by agent UUID"),
    status: str | None = Query(None, description="Filter by status"),
    action_type: str | None = Query(None, description="Filter by action type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Return recent action requests, newest first."""
    query = select(ActionRequest).order_by(desc(ActionRequest.submitted_at))
    if agent_id:
        try:
            query = query.where(ActionRequest.agent_id == uuid.UUID(agent_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="agent_id must be a valid UUID")
    if status:
        query = query.where(ActionRequest.status == status)
    if action_type:
        query = query.where(ActionRequest.action_type == action_type.upper())

    query = query.limit(limit).offset(offset)
    result = await session.execute(query)
    records = list(result.scalars().all())

    return {
        "status": "success",
        "code": "ACTIONS_LISTED",
        "message": f"Returned {len(records)} action request(s).",
        "data": {
            "actions": [_ar_to_dict(ar) for ar in records],
            "count": len(records),
        },
        "request_id": None,
    }


@router.get("/{request_id}", summary="Get a single action request by ID")
async def get_action(
    request_id: str,
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Return details for a single action request."""
    try:
        req_uuid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="request_id must be a valid UUID")

    result = await session.execute(
        select(ActionRequest).where(ActionRequest.id == req_uuid)
    )
    ar = result.scalar_one_or_none()
    if ar is None:
        raise HTTPException(
            status_code=404,
            detail=f"Action request {request_id!r} not found.",
        )

    return {
        "status": "success",
        "code": "ACTION_FOUND",
        "message": "Action request retrieved.",
        "data": _ar_to_dict(ar),
        "request_id": request_id,
    }
