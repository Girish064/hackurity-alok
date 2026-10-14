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


def _events_to_list(events) -> list[dict[str, Any]]:
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


@router.get("", summary="Retrieve audit events (standard contract)")
async def get_audit_envelope(
    actor_id: str | None = Query(None, description="Filter by agent/actor ID"),
    event_type: str | None = Query(None, description="Filter by event type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Return audit events using the standard V3 response envelope."""
    events = await get_events(session, actor_id, event_type, limit, offset)
    records = _events_to_list(events)
    return {
        "status": "success",
        "code": "AUDIT_EVENTS_LISTED",
        "message": f"Returned {len(records)} audit event(s).",
        "data": {
            "events": records,
            "count": len(records),
        },
        "request_id": None,
    }


@router.get("/events", summary="List audit events (legacy list format)")
async def list_audit_events(
    actor_id: str | None = Query(None, description="Filter by agent/actor ID"),
    event_type: str | None = Query(None, description="Filter by event type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(db_session),
) -> list[dict[str, Any]]:
    """Return raw audit events list in chain order."""
    events = await get_events(session, actor_id, event_type, limit, offset)
    return _events_to_list(events)


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
