"""
backend/api/audit.py
Audit event query and chain verification endpoints.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.admin_auth import get_admin_identity
from backend.dependencies import db_session
from backend.services.audit_service import get_events, verify_chain

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events", summary="List audit events")
async def list_audit_events(
    actor_id: str | None = Query(None, description="Filter by agent/actor ID"),
    event_type: str | None = Query(None, description="Filter by event type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(db_session),
) -> list[dict[str, Any]]:
    """
    Return audit events in chain order.
    No admin auth required (events are non-sensitive; adjust if needed).
    """
    events = await get_events(session, actor_id, event_type, limit, offset)
    return [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "event_data": e.event_data,
            "actor_id": e.actor_id,
            "timestamp": e.timestamp.isoformat(),
            "prev_chain_hash": e.prev_chain_hash,
            "chain_hash": e.chain_hash,
            "sequence_number": e.sequence_number,
        }
        for e in events
    ]


@router.post("/verify-chain", summary="Verify audit chain integrity (admin)")
async def verify_audit_chain_endpoint(
    session: AsyncSession = Depends(db_session),
    admin: str = Depends(get_admin_identity),
) -> dict[str, Any]:
    """
    Load all audit events and verify the hash chain.

    LIMITATION: Only detects modification or reordering of the returned records.
    Cannot detect deletion of records or replacement of the entire chain.
    """
    result = await verify_chain(session)
    return {
        "valid": result.valid,
        "verified_count": result.verified_count,
        "first_broken_index": result.first_broken_index,
        "error_message": result.error_message,
        "limitation": (
            "This check verifies modification and reordering of records returned "
            "by the query. It cannot detect deletion of records or full chain "
            "replacement."
        ),
    }
