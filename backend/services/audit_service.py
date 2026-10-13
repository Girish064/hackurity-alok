"""
backend/services/audit_service.py
Builds and persists tamper-evident audit events.

Alok's backend calls Girish's append_audit_record() to build AuditRecords,
then persists the results here. Girish does NOT write to the database.

LIMITATION (documented per architecture review):
  The hash chain detects modification or reordering within the supplied
  ordered records. It cannot detect deletion or chain replacement.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import security as sec
from backend.storage.models.audit_event import AuditEvent


async def _get_last_chain_hash(session: AsyncSession) -> str | None:
    """Return the chain_hash of the most recent audit event, or None."""
    result = await session.execute(
        select(AuditEvent.chain_hash)
        .order_by(AuditEvent.sequence_number.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row


async def _get_next_sequence(session: AsyncSession) -> int:
    """Return the next sequence number from the DB sequence (or max+1 for SQLite)."""
    bind = session.get_bind()
    if hasattr(bind, "dialect") and bind.dialect.name == "sqlite":
        result = await session.execute(
            select(func.coalesce(func.max(AuditEvent.sequence_number), 0) + 1)
        )
        return result.scalar_one()
    result = await session.execute(func.nextval("audit_event_seq"))
    return result.scalar_one()


async def append_event(
    session: AsyncSession,
    event_type: str,
    event_data: dict,
    actor_id: str,
) -> AuditEvent:
    """
    Build a new audit record via Girish's security module and persist it.

    The chain is linked to the most recent event in the database.
    This method must be called within a transaction to prevent sequence gaps.
    """
    prev_hash = await _get_last_chain_hash(session)
    seq = await _get_next_sequence(session)

    # Delegate hash-chain computation to Girish's security module
    audit_record = sec.append_audit_record(
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        prev_chain_hash=prev_hash,
    )

    event = AuditEvent(
        id=uuid.UUID(audit_record.event_id),
        event_type=audit_record.event_type,
        event_data=audit_record.event_data,
        actor_id=audit_record.actor_id,
        timestamp=datetime.fromisoformat(audit_record.timestamp),
        prev_chain_hash=audit_record.prev_chain_hash,
        chain_hash=audit_record.chain_hash,
        sequence_number=seq,
    )
    session.add(event)
    await session.flush()
    return event


async def get_events(
    session: AsyncSession,
    actor_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    """Return audit events, optionally filtered."""
    query = select(AuditEvent).order_by(AuditEvent.sequence_number)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)
    if event_type:
        query = query.where(AuditEvent.event_type == event_type)
    query = query.limit(limit).offset(offset)
    result = await session.execute(query)
    return list(result.scalars().all())


async def verify_chain(session: AsyncSession) -> sec.AuditChainVerificationResult:
    """
    Load all audit events in order and run verify_audit_chain().

    LIMITATION: Only detects modification/reordering of records returned
    by this query. Deleted or replaced records are not detectable.
    """
    result = await session.execute(
        select(AuditEvent).order_by(AuditEvent.sequence_number)
    )
    db_events = list(result.scalars().all())

    def _to_iso(dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    records = [
        sec.AuditRecord(
            event_id=str(e.id),
            event_type=e.event_type,
            event_data=e.event_data,
            actor_id=e.actor_id,
            timestamp=_to_iso(e.timestamp),
            prev_chain_hash=e.prev_chain_hash,
            chain_hash=e.chain_hash,
        )
        for e in db_events
    ]
    return sec.verify_audit_chain(records)
