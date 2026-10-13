"""
backend/storage/models/action_request.py
ORM model for submitted action requests (gateway records).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.storage.database import Base


class ActionRequest(Base):
    __tablename__ = "action_requests"

    # request_id provided by the client (idempotency key)
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False)
    action_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_decision: Mapped[str] = mapped_column(
        Enum("ALLOW", "DENY", "REQUIRE_APPROVAL", name="policy_decision"),
        nullable=False,
    )
    capability_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    capability_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, unique=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "pending",
            "awaiting_approval",
            "approved",
            "denied",
            "capability_issued",
            "executed",
            name="action_request_status",
        ),
        nullable=False,
        default="pending",
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<ActionRequest id={self.id} action_type={self.action_type!r} "
            f"status={self.status}>"
        )
