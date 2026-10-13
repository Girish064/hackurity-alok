"""
backend/api/approvals.py
Human approval workflow endpoints.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.admin_auth import get_admin_identity
from backend.dependencies import db_session
from backend.services.approval_service import (
    decide_approval,
    get_approval,
    list_pending_approvals,
)

router = APIRouter(prefix="/approvals", tags=["Approvals"])


class DecideRequest(BaseModel):
    decision: str   # "approved" | "rejected"
    decided_by: str


@router.get("", summary="List pending approval requests (admin)")
async def list_approvals(
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> list[dict[str, Any]]:
    approvals = await list_pending_approvals(session)
    return [_approval_to_dict(a) for a in approvals]


@router.get("/{approval_id}", summary="Get approval request details (admin)")
async def get_approval_endpoint(
    approval_id: str,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    approval = await get_approval(session, approval_id)
    return _approval_to_dict(approval)


@router.post("/{approval_id}/decide", summary="Approve or reject an action (admin)")
async def decide_approval_endpoint(
    approval_id: str,
    body: DecideRequest,
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    """
    Approve or reject a pending action.

    Security guarantee: This decision is bound to the exact action_digest stored
    in the approval record. The agent cannot use this approval for a different action.

    After approving, the agent re-submits the original request_id to
    POST /gateway/actions/submit to receive the capability token.
    """
    if body.decision not in ("approved", "rejected"):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail="decision must be 'approved' or 'rejected'",
        )

    approval = await decide_approval(
        session=session,
        approval_id=approval_id,
        decision=body.decision,
        decided_by=body.decided_by,
    )
    return {
        **_approval_to_dict(approval),
        "message": (
            f"Approval {approval_id!r} has been {body.decision}. "
            "The agent may re-submit the original request_id to receive a capability token."
            if body.decision == "approved"
            else f"Approval {approval_id!r} has been rejected."
        ),
    }


def _approval_to_dict(a: Any) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "action_request_id": str(a.action_request_id),
        "agent_id": str(a.agent_id),
        "tenant_id": str(a.tenant_id),
        "action_digest": a.action_digest,
        "status": a.status,
        "decided_by": a.decided_by,
        "decided_at": a.decided_at.isoformat() if a.decided_at else None,
        "expires_at": a.expires_at.isoformat(),
        "created_at": a.created_at.isoformat(),
    }
