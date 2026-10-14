"""
backend/api/receipts.py
Execution receipt query and verification endpoints.

Uses the existing security module's verify_execution_receipt() adapter.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

import security as sec
from backend.config import get_settings
from backend.dependencies import db_session
from backend.storage.models.execution import Execution

router = APIRouter(prefix="/receipts", tags=["Receipts"])


class VerifyReceiptRequest(BaseModel):
    receipt_token: str = Field(..., min_length=1, description="Signed receipt JWT")


def _execution_to_dict(ex: Execution) -> dict[str, Any]:
    return {
        "execution_id": str(ex.id),
        "capability_id": str(ex.capability_id),
        "agent_id": str(ex.agent_id),
        "tenant_id": str(ex.tenant_id),
        "tool_name": ex.tool_name,
        "action_digest": ex.action_digest,
        "outcome": ex.outcome,
        "outcome_data": ex.outcome_data,
        "has_receipt": bool(ex.receipt_token),
        "executed_at": ex.executed_at.isoformat() if ex.executed_at else None,
    }


@router.get("", summary="List execution receipts")
async def list_receipts(
    agent_id: str | None = Query(None, description="Filter by agent UUID"),
    outcome: str | None = Query(None, description="Filter by outcome (success/failure/tool_error)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Return execution records with their receipt availability."""
    query = select(Execution).order_by(desc(Execution.executed_at))
    if agent_id:
        try:
            query = query.where(Execution.agent_id == uuid.UUID(agent_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="agent_id must be a valid UUID")
    if outcome:
        query = query.where(Execution.outcome == outcome.lower())

    query = query.limit(limit).offset(offset)
    result = await session.execute(query)
    records = list(result.scalars().all())

    return {
        "status": "success",
        "code": "RECEIPTS_LISTED",
        "message": f"Returned {len(records)} execution record(s).",
        "data": {
            "receipts": [_execution_to_dict(ex) for ex in records],
            "count": len(records),
        },
        "request_id": None,
    }


@router.post("/verify", summary="Verify an execution receipt")
async def verify_receipt(
    body: VerifyReceiptRequest,
) -> dict[str, Any]:
    """
    Verify a signed execution receipt using the existing security module.
    Returns the verified claims or the specific verification failure.
    """
    settings = get_settings()
    try:
        result = sec.verify_execution_receipt(
            token=body.receipt_token,
            verifying_key=settings.verifying_key,
        )
        return {
            "status": "success",
            "code": "RECEIPT_VALID",
            "message": "Receipt signature and claims verified successfully.",
            "data": {
                "valid": True,
                "capability_id": result.capability_id,
                "action_digest": result.action_digest,
                "executor_id": result.executor_id,
                "outcome": result.outcome,
                "executed_at": result.executed_at,
                "verified": True,
            },
            "request_id": None,
        }
    except sec.ReceiptVerificationError as exc:
        return {
            "status": "blocked",
            "code": "RECEIPT_INVALID",
            "message": f"Receipt verification failed: {exc}",
            "data": {
                "valid": False,
                "error": str(exc),
            },
            "request_id": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "RECEIPT_VERIFY_ERROR",
            "message": f"Unexpected error during receipt verification: {exc}",
            "data": {"valid": False},
            "request_id": None,
        }
