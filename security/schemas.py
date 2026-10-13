"""
security/schemas.py
Shared data-transfer objects used across all security module interfaces.

Ownership: Girish defines these; Alok imports them.
This file is the authoritative source for all shared security schemas.

ASSUMPTION (documented per implementation plan):
  - Monetary amounts in `parameters` are always strings (e.g. "500.00") to
    ensure deterministic serialization without floating-point ambiguity.
  - The domain-separation prefix for canonicalization is "agentshield-action-v1:".
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ActionRequest:
    """
    The canonical schema for an action submitted by an agent.
    Both the gateway and the executor use this exact structure.
    """
    agent_id: str           # UUID string
    tenant_id: str          # UUID string
    action_type: str        # e.g. "ISSUE_REFUND"
    parameters: dict        # JSON-serializable; amounts must be strings
    request_id: str         # Client-generated UUID idempotency key
    submitted_at: str       # ISO-8601 UTC


@dataclass
class CapabilityToken:
    """Returned by issue_capability()."""
    token: str              # Signed JWT (EdDSA / Ed25519)
    capability_id: str      # jti claim — used for replay prevention
    expires_at: str         # ISO-8601 UTC


@dataclass
class CapabilityClaims:
    """Returned by verify_capability() on success."""
    capability_id: str
    agent_id: str
    tenant_id: str
    action_digest: str
    executor_id: str
    expires_at: datetime
    approval_ref: str | None
    issued_at: datetime


@dataclass
class ApprovalRecord:
    """
    Passed to verify_approval() by Alok's backend.
    Alok fetches this from the DB; Girish verifies its integrity.
    """
    approval_id: str
    action_request_id: str
    agent_id: str
    action_digest: str      # The digest this approval is bound to
    action_hmac: str        # HMAC(approval_id ‖ action_digest) — DB integrity
    status: str             # "approved" | "rejected" | "pending" | "expired"
    decided_by: str | None
    decided_at: str | None
    expires_at: str


@dataclass
class AuditRecord:
    """
    Returned by append_audit_record().
    Alok's backend persists this; Girish does NOT write to the DB.
    """
    event_id: str           # UUID
    event_type: str
    event_data: dict
    actor_id: str
    timestamp: str          # ISO-8601 UTC
    prev_chain_hash: str | None
    chain_hash: str         # SHA-256(prev_chain_hash ‖ event_bytes)


@dataclass
class AuditChainVerificationResult:
    """Returned by verify_audit_chain()."""
    valid: bool
    verified_count: int
    first_broken_index: int | None
    error_message: str | None
