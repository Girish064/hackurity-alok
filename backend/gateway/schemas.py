"""
backend/gateway/schemas.py
Pydantic request/response schemas for the gateway endpoint.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ActionSubmitRequest(BaseModel):
    """
    Body of POST /gateway/actions/submit.

    `request_id` is a client-generated UUID used as an idempotency key.
    If the same request_id is submitted again, the original decision is returned
    without re-evaluating policy.

    Amounts in `parameters` MUST be strings (e.g. "500.00") to ensure
    deterministic canonicalization. The backend validates this for refund actions.
    """
    action_type: str = Field(..., min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    request_id: UUID = Field(
        ..., description="Client-generated UUID for idempotency"
    )

    @field_validator("action_type")
    @classmethod
    def action_type_uppercase(cls, v: str) -> str:
        return v.upper().strip()


class ActionSubmitResponse(BaseModel):
    """Response for a successfully authorized action (ALLOW path)."""
    request_id: str
    decision: str                     # "ALLOW"
    capability_token: str
    action_digest: str
    expires_at: str


class ApprovalRequiredResponse(BaseModel):
    """Response when a human approval is required before capability issuance."""
    request_id: str
    decision: str                     # "REQUIRE_APPROVAL"
    approval_id: str
    message: str


class DeniedResponse(BaseModel):
    """Response for a hard policy denial."""
    request_id: str
    decision: str                     # "DENY"
    reason: str
