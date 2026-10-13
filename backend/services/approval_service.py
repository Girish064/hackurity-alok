"""
backend/services/approval_service.py
Human approval state machine.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.exceptions import (
    ApprovalAlreadyDecidedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
)
from backend.storage.models.approval import ApprovalRequest
from backend.storage.models.action_request import ActionRequest
import security as sec


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def create_approval_request(
    session: AsyncSession,
    action_request: ActionRequest,
    action_digest: str,
) -> ApprovalRequest:
    """
    Create a pending ApprovalRequest bound to the exact action digest.
    The HMAC binds (approval_id ‖ action_digest) together for integrity.
    """
    settings = get_settings()
    approval_id = str(uuid.uuid4())
    action_hmac = sec.compute_approval_hmac(
        approval_id,
        action_digest,
        settings.admin_secret_token,
    )
    expires_at = _now() + timedelta(seconds=settings.approval_ttl_seconds)

    approval = ApprovalRequest(
        id=uuid.UUID(approval_id),
        action_request_id=action_request.id,
        agent_id=action_request.agent_id,
        tenant_id=action_request.tenant_id,
        action_digest=action_digest,
        action_hmac=action_hmac,
        status="pending",
        expires_at=expires_at,
        created_at=_now(),
    )
    session.add(approval)
    await session.flush()
    return approval


async def get_approval(
    session: AsyncSession, approval_id: str
) -> ApprovalRequest:
    """Fetch an approval request or raise ApprovalNotFoundError."""
    result = await session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.id == uuid.UUID(approval_id)
        )
    )
    approval = result.scalar_one_or_none()
    if approval is None:
        raise ApprovalNotFoundError(f"Approval {approval_id!r} not found.")
    return approval


async def get_approval_for_action(
    session: AsyncSession, action_request_id: str
) -> ApprovalRequest | None:
    """Return the approval record for a given action request, or None."""
    result = await session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.action_request_id == uuid.UUID(action_request_id)
        )
    )
    return result.scalar_one_or_none()


async def decide_approval(
    session: AsyncSession,
    approval_id: str,
    decision: str,  # "approved" | "rejected"
    decided_by: str,
) -> ApprovalRequest:
    """
    Apply an admin's decision to an approval request.
    Raises ApprovalAlreadyDecidedError if already decided.
    Raises ApprovalExpiredError if the request has expired.
    """
    approval = await get_approval(session, approval_id)

    if approval.status not in ("pending",):
        raise ApprovalAlreadyDecidedError(
            f"Approval {approval_id!r} is already in state {approval.status!r}."
        )

    now = _now()
    expires_at = approval.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        approval.status = "expired"
        await session.flush()
        raise ApprovalExpiredError(
            f"Approval {approval_id!r} expired at {expires_at.isoformat()}."
        )

    approval.status = decision  # "approved" or "rejected"
    approval.decided_by = decided_by
    approval.decided_at = now
    await session.flush()
    return approval


async def list_pending_approvals(session: AsyncSession) -> list[ApprovalRequest]:
    """Return all pending (non-expired) approval requests."""
    result = await session.execute(
        select(ApprovalRequest).where(ApprovalRequest.status == "pending")
    )
    return list(result.scalars().all())
