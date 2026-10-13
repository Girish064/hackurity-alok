"""
backend/executor/schemas.py
Pydantic request/response schemas for the executor endpoint.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ExecuteRequest(BaseModel):
    """
    Body of POST /executor/execute.

    The agent must present:
    - The capability_token received from the gateway.
    - The exact same action_type and parameters used when requesting the capability.
      Any change — even a minor one — will cause the digest re-computation to fail.
    """
    capability_token: str = Field(..., min_length=1)
    action_type: str = Field(..., min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ExecuteResponse(BaseModel):
    """Successful execution response."""
    execution_id: str
    outcome: str                    # "success" | "failure" | "tool_error"
    outcome_data: dict[str, Any]
    receipt_token: str
    executed_at: str
