"""
backend/storage/models/execution.py
ORM model for protected-tool execution records.
Each capability may appear at most once in this table (UNIQUE on capability_id).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.storage.database import Base


class Execution(Base):
    __tablename__ = "executions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("action_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    # UNIQUE enforces at-most-one execution per capability at the DB level.
    capability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True, index=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    parameters_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False)
    action_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(
        Enum("success", "failure", "tool_error", name="execution_outcome"),
        nullable=False,
    )
    outcome_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    receipt_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<Execution id={self.id} tool={self.tool_name!r} outcome={self.outcome}>"
        )
