"""
core/baseline.py
Baseline A/B/C configuration for the AgentShield demonstration.

SAFETY NOTE:
  Baselines A and B are INTENTIONALLY VULNERABLE test configurations.
  They must only be used with synthetic data and a local mock executor.
  They MUST NOT be exposed to real external services.
  Full enforcement (C) is the only production-safe configuration.

Baseline A — Minimal protection:
  - Policy evaluation: YES (hard denials still enforced)
  - Capability issuance: YES (signed)
  - Action digest check in executor: NO  ← vulnerable
  - Capability signature verification: NO  ← vulnerable
  - Replay guard: NO  ← vulnerable
  - Agent kill-switch check: NO  ← vulnerable
  Use-case: shows what happens with NO independent enforcement.

Baseline B — Gateway-only protection:
  - Policy evaluation: YES
  - Capability issuance: YES (signed)
  - Action digest check in executor: NO  ← vulnerable
  - Capability signature verification: YES  ← partial
  - Replay guard: NO  ← vulnerable
  - Agent kill-switch check: YES
  Use-case: shows that perimeter checks alone are insufficient.

Baseline C — Full AgentShield enforcement (default, production-safe):
  - All checks: YES
  - Independent executor verification: YES
  - Replay guard: YES
  - Kill-switch: YES
  Use-case: mathematically guaranteed enforcement boundary.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class BaselineID(str, Enum):
    A = "A"
    B = "B"
    C = "C"


@dataclass(frozen=True)
class BaselineConfig:
    """Describes the security checks active for a given baseline."""
    id: BaselineID
    name: str
    description: str

    # Control plane
    policy_evaluation: bool
    capability_issuance: bool

    # Execution plane checks
    check_action_digest: bool       # Re-compute digest from parameters and compare
    verify_capability_signature: bool
    check_replay_guard: bool        # Atomic capability consumption
    check_agent_kill_switch: bool

    # Risk label
    risk_level: str                 # "critical" | "high" | "low"

    def as_dict(self) -> dict:
        return {
            "id": self.id.value,
            "name": self.name,
            "description": self.description,
            "checks": {
                "policy_evaluation": self.policy_evaluation,
                "capability_issuance": self.capability_issuance,
                "check_action_digest": self.check_action_digest,
                "verify_capability_signature": self.verify_capability_signature,
                "check_replay_guard": self.check_replay_guard,
                "check_agent_kill_switch": self.check_agent_kill_switch,
            },
            "risk_level": self.risk_level,
        }


# ── Baseline definitions ───────────────────────────────────────────────────

BASELINE_A = BaselineConfig(
    id=BaselineID.A,
    name="Minimal Protection",
    description=(
        "Demonstration baseline with deliberate security gaps. "
        "The executor runs the tool after checking the capability exists, "
        "but does NOT re-verify the signature, re-compute the digest, "
        "check for replay, or consult the kill-switch. "
        "A tampered action or replayed capability will execute. "
        "SYNTHETIC DATA ONLY — not safe for production."
    ),
    policy_evaluation=True,
    capability_issuance=True,
    check_action_digest=False,
    verify_capability_signature=False,
    check_replay_guard=False,
    check_agent_kill_switch=False,
    risk_level="critical",
)

BASELINE_B = BaselineConfig(
    id=BaselineID.B,
    name="Gateway-Only Protection",
    description=(
        "Gateway enforces policy and issues a signed capability. "
        "The executor checks the signature and kill-switch, "
        "but does NOT re-compute the action digest (tampered parameters can execute) "
        "and does NOT enforce replay prevention. "
        "Illustrates the limits of perimeter-only checks. "
        "SYNTHETIC DATA ONLY — not safe for production."
    ),
    policy_evaluation=True,
    capability_issuance=True,
    check_action_digest=False,
    verify_capability_signature=True,
    check_replay_guard=False,
    check_agent_kill_switch=True,
    risk_level="high",
)

BASELINE_C = BaselineConfig(
    id=BaselineID.C,
    name="Full AgentShield Enforcement",
    description=(
        "Every security check is active. "
        "The executor independently re-computes the action digest, "
        "verifies the capability signature, enforces atomic replay prevention, "
        "and checks the agent kill-switch. "
        "A tampered, expired, revoked, or replayed action is always rejected. "
        "This is the only production-safe configuration."
    ),
    policy_evaluation=True,
    capability_issuance=True,
    check_action_digest=True,
    verify_capability_signature=True,
    check_replay_guard=True,
    check_agent_kill_switch=True,
    risk_level="low",
)

ALL_BASELINES: dict[BaselineID, BaselineConfig] = {
    BaselineID.A: BASELINE_A,
    BaselineID.B: BASELINE_B,
    BaselineID.C: BASELINE_C,
}

# ── Runtime baseline state ──────────────────────────────────────────────────
# This is the in-process baseline. The canonical store is Redis.
# It defaults to C on startup and is overridden by the /config endpoint.

_active_baseline: BaselineID = BaselineID.C
_REDIS_KEY = "agentshield:active_baseline"


def get_active_baseline_id() -> BaselineID:
    """Return the currently active baseline ID (in-process cache)."""
    return _active_baseline


def get_active_baseline() -> BaselineConfig:
    """Return the currently active baseline configuration."""
    return ALL_BASELINES[_active_baseline]


def set_active_baseline(baseline_id: BaselineID) -> BaselineConfig:
    """
    Set the active baseline in-process.
    Callers must also persist to Redis for cross-process consistency.
    """
    global _active_baseline
    _active_baseline = baseline_id
    return ALL_BASELINES[baseline_id]


async def load_baseline_from_redis(redis) -> BaselineID:
    """
    Load the active baseline from Redis on startup.
    Falls back to C if Redis is unavailable or key is missing.
    """
    global _active_baseline
    try:
        stored = await redis.get(_REDIS_KEY)
        if stored and stored in BaselineID._value2member_map_:
            _active_baseline = BaselineID(stored)
    except Exception:
        pass  # Fall back to default C
    return _active_baseline


async def persist_baseline_to_redis(redis, baseline_id: BaselineID) -> None:
    """Persist the baseline selection to Redis."""
    await redis.set(_REDIS_KEY, baseline_id.value)
