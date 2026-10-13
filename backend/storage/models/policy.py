"""
backend/storage/models/policy.py
ORM model for tenant-level authorization policies.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Numeric, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.storage.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    decision: Mapped[str] = mapped_column(
        Enum("ALLOW", "DENY", "REQUIRE_APPROVAL", name="policy_decision"),
        nullable=False,
    )
    # For ALLOW: actions with amount <= max_amount are auto-approved
    # For REQUIRE_APPROVAL: amounts > requires_approval_above need human sign-off
    max_amount: Mapped[float | None] = mapped_column(Numeric(12, 2), nullable=True)
    requires_approval_above: Mapped[float | None] = mapped_column(
        Numeric(12, 2), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<Policy id={self.id} action_type={self.action_type!r} "
            f"decision={self.decision}>"
        )
