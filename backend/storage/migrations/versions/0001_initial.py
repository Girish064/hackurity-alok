"""
backend/storage/migrations/versions/0001_initial.py
Initial database schema migration.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Enums ─────────────────────────────────────────────────────────────
    op.execute("CREATE TYPE agent_status AS ENUM ('active', 'revoked', 'suspended')")
    op.execute("CREATE TYPE policy_decision AS ENUM ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')")
    op.execute(
        "CREATE TYPE action_request_status AS ENUM "
        "('pending', 'awaiting_approval', 'approved', 'denied', 'capability_issued', 'executed')"
    )
    op.execute(
        "CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected', 'expired')"
    )
    op.execute(
        "CREATE TYPE execution_outcome AS ENUM ('success', 'failure', 'tool_error')"
    )

    # ── agents ────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("api_key_hash", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.Enum("active", "revoked", "suspended", name="agent_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
        sa.Column("permissions", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("max_refund_amount", sa.Numeric(12, 2), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agents_tenant_status", "agents", ["tenant_id", "status"])
    op.create_index("ix_agents_api_key_hash", "agents", ["api_key_hash"], unique=True)
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])

    # ── policies ──────────────────────────────────────────────────────────
    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column(
            "decision",
            sa.Enum("ALLOW", "DENY", "REQUIRE_APPROVAL", name="policy_decision", create_type=False),
            nullable=False,
        ),
        sa.Column("max_amount", sa.Numeric(12, 2), nullable=True),
        sa.Column("requires_approval_above", sa.Numeric(12, 2), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policies_tenant_id", "policies", ["tenant_id"])

    # ── action_requests ───────────────────────────────────────────────────
    op.create_table(
        "action_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("action_digest", sa.String(64), nullable=True),
        sa.Column(
            "policy_decision",
            sa.Enum("ALLOW", "DENY", "REQUIRE_APPROVAL", name="policy_decision", create_type=False),
            nullable=False,
        ),
        sa.Column("capability_token", sa.Text(), nullable=True),
        sa.Column("capability_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "awaiting_approval",
                "approved",
                "denied",
                "capability_issued",
                "executed",
                name="action_request_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_action_requests_agent_id", "action_requests", ["agent_id"])
    op.create_index("ix_action_requests_tenant_id", "action_requests", ["tenant_id"])
    op.create_index(
        "ix_action_requests_capability_id", "action_requests", ["capability_id"], unique=True
    )

    # ── approval_requests ─────────────────────────────────────────────────
    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "action_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("action_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "agent_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_digest", sa.String(64), nullable=False),
        sa.Column("action_hmac", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "approved",
                "rejected",
                "expired",
                name="approval_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_approval_requests_action_request_id", "approval_requests", ["action_request_id"], unique=True)
    op.create_index("ix_approval_requests_agent_id", "approval_requests", ["agent_id"])

    # ── executions ────────────────────────────────────────────────────────
    op.create_table(
        "executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "action_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("action_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("capability_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("parameters_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("action_digest", sa.String(64), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "success",
                "failure",
                "tool_error",
                name="execution_outcome",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("outcome_data", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("receipt_token", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_executions_action_request_id", "executions", ["action_request_id"])
    op.create_index("ix_executions_capability_id", "executions", ["capability_id"], unique=True)
    op.create_index("ix_executions_agent_id", "executions", ["agent_id"])

    # ── audit_events ──────────────────────────────────────────────────────
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("event_data", postgresql.JSONB(), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_chain_hash", sa.String(64), nullable=True),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_events_sequence_number", "audit_events", ["sequence_number"], unique=True)

    # Sequence for monotonic ordering
    op.execute("CREATE SEQUENCE audit_event_seq START 1")


def downgrade() -> None:
    op.execute("DROP SEQUENCE IF EXISTS audit_event_seq")
    op.drop_table("audit_events")
    op.drop_table("executions")
    op.drop_table("approval_requests")
    op.drop_table("action_requests")
    op.drop_table("policies")
    op.drop_table("agents")
    op.execute("DROP TYPE IF EXISTS execution_outcome")
    op.execute("DROP TYPE IF EXISTS approval_status")
    op.execute("DROP TYPE IF EXISTS action_request_status")
    op.execute("DROP TYPE IF EXISTS policy_decision")
    op.execute("DROP TYPE IF EXISTS agent_status")
