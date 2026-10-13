"""
backend/policy/models.py
Policy decision types and result dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class PolicyDecision:
    decision: Decision
    reason: str
    # Populated only for REQUIRE_APPROVAL
    approval_threshold: float | None = None
