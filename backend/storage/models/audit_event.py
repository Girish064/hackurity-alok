"""
backend/storage/models/audit_event.py
ORM model for tamper-evident audit events.

The hash chain is computed by Girish's security module (append_audit_record).
This table persists the AuditRecord it returns.

LIMITATION (documented per architecture review):
  The hash chain detects modification or reordering of the records supplied
  to verify_audit_chain(). It CANNOT detect deletion of records or replacement
  of the entire chain. Do not claim stronger guarantees than this.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.storage.database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # event_id comes from AuditRecord.event_id (set by security module)
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    prev_chain_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Monotonically increasing sequence for reliable ordering
    sequence_number: Mapped[int] = mapped_column(
        BigInteger, nullable=False, unique=True, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} type={self.event_type!r} "
            f"seq={self.sequence_number}>"
        )
