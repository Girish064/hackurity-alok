"""
core/adaptive_policy.py
Adaptive Policy Engine — Confidence-Based Scope and Expiry Control.

Design principles:
  - All scoring is deterministic and explainable from defined inputs.
  - No AI/LLM output is used as the sole security decision.
  - Hard denials from the base policy engine cannot be overridden here.
  - Missing or contradictory security context fails closed (score = 0.0).
  - Suspicious activity never increases trust.
  - The engine produces an explainable structured decision with audit trail.

Confidence score range: 0.0 (fully reject) → 1.0 (fully trust)
Risk classification:
  HIGH   : 0.0 – 0.39  — narrow scope, short TTL, human approval often required
  MEDIUM : 0.4 – 0.69  — standard scope, moderate TTL
  LOW    : 0.7 – 1.0   — broad scope, full TTL

Scoring inputs (all deterministic):
  +0.25  agent is in a known trusted role
  +0.20  action type is within the agent's permitted set
  +0.15  requested scope ≤ configured maximum scope
  +0.15  context validation passed (e.g., tenant isolation confirmed)
  +0.10  action type has LOW sensitivity
  -0.20  action type has HIGH sensitivity (overrides LOW bonus)
  -0.30  recent suspicious activity detected (non-additive with low confidence)
  -0.40  context validation FAILED (hard penalizer — missing/contradictory context)
  -0.50  requested scope EXCEEDS maximum permitted scope (forces deny)
  0.00   missing required context field (score clamped to 0.0, result = DENY)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ── Enums ──────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"  # Used only when score = 0.0 or hard-denied


class PolicyOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# ── Configuration ─────────────────────────────────────────────────────────


# Sensitivity labels for known action types.
# Unlisted action types default to MEDIUM sensitivity.
ACTION_SENSITIVITY: dict[str, str] = {
    "SEND_EMAIL": "LOW",
    "READ_RECORD": "LOW",
    "ISSUE_REFUND": "HIGH",
    "TRANSFER_FUNDS": "HIGH",
    "DELETE_RECORD": "HIGH",
    "MODIFY_PERMISSIONS": "HIGH",
    "EXPORT_DATA": "HIGH",
    "RESET_PASSWORD": "MEDIUM",
    "CREATE_RECORD": "MEDIUM",
    "UPDATE_RECORD": "MEDIUM",
}

# Known trusted roles and their base trust contribution
TRUSTED_ROLES: dict[str, float] = {
    "support_agent": 0.25,
    "finance_agent": 0.25,
    "admin_agent": 0.20,   # Admin has broad scope but we keep trust bounded
    "read_only": 0.15,
    "demo_agent": 0.20,
}

# Default scope limits by action type
# Scope here means the maximum permitted operation scope (e.g., max amount as float)
DEFAULT_SCOPE_LIMITS: dict[str, float] = {
    "ISSUE_REFUND": 10_000.0,
    "TRANSFER_FUNDS": 5_000.0,
    "EXPORT_DATA": 1_000.0,      # max records
    "DELETE_RECORD": 100.0,      # max records
    "SEND_EMAIL": 100.0,         # max recipients
    "CREATE_RECORD": 1_000.0,
}

# Maximum capability TTL in seconds by risk level
TTL_BY_RISK: dict[RiskLevel, int] = {
    RiskLevel.LOW: 600,       # 10 minutes
    RiskLevel.MEDIUM: 300,    # 5 minutes
    RiskLevel.HIGH: 120,      # 2 minutes
    RiskLevel.CRITICAL: 0,    # Denied — TTL irrelevant
}

# Minimum confidence required for auto-approval (below this = REQUIRE_APPROVAL)
MIN_CONFIDENCE_AUTO_APPROVE: float = 0.60

# Actions that ALWAYS require human approval regardless of confidence
ALWAYS_REQUIRES_APPROVAL: frozenset[str] = frozenset({
    "TRANSFER_FUNDS",
    "MODIFY_PERMISSIONS",
})


# ── Input/Output schemas ───────────────────────────────────────────────────


@dataclass
class AdaptivePolicyInput:
    """
    Context provided to the adaptive policy engine.
    All fields are required; missing/None values are treated as failures.
    """
    # Agent identity
    agent_id: str
    agent_role: str                  # Must be in TRUSTED_ROLES for role bonus
    permitted_actions: list[str]     # List of action types this agent is allowed

    # Action
    action_type: str
    requested_scope: float           # Numeric scope (amount, count, etc.) — 0 if N/A

    # Context validation
    context_valid: bool              # Did upstream validation (e.g., tenant check) pass?
    context_reason: str              # Human-readable explanation of context validation

    # Behavioral context
    recent_failures: int = 0         # Count of recent denied/suspicious requests (non-negative)
    suspicious_activity: bool = False

    # Policy overrides (from current baseline or admin config)
    max_scope_override: Optional[float] = None
    policy_version: str = "v1"


@dataclass
class AdaptivePolicyDecision:
    """
    Structured decision returned by the adaptive policy engine.
    Includes full audit trail for the dashboard and CLI.
    """
    # Core decision
    outcome: PolicyOutcome
    confidence: float               # 0.0 – 1.0
    risk_level: RiskLevel

    # Scope and TTL
    allowed_scope: float            # May be narrower than requested_scope
    capability_ttl_seconds: int

    # Approval
    requires_human_approval: bool
    approval_reason: Optional[str]

    # Explanation
    rule_ids: list[str]             # IDs of scoring rules that fired
    explanation: str                # Human-readable policy reasoning

    # Metadata
    evaluated_at: float = field(default_factory=time.time)
    policy_version: str = "v1"

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "confidence": self.confidence,
            "risk_level": self.risk_level.value,
            "allowed_scope": self.allowed_scope,
            "capability_ttl_seconds": self.capability_ttl_seconds,
            "requires_human_approval": self.requires_human_approval,
            "approval_reason": self.approval_reason,
            "rule_ids": self.rule_ids,
            "explanation": self.explanation,
            "evaluated_at": self.evaluated_at,
            "policy_version": self.policy_version,
        }


# ── Engine ─────────────────────────────────────────────────────────────────


def evaluate_adaptive_policy(
    inp: AdaptivePolicyInput,
    max_scope_limit: Optional[float] = None,
) -> AdaptivePolicyDecision:
    """
    Evaluate the adaptive policy for the given context.

    Parameters
    ----------
    inp : AdaptivePolicyInput
        Full context for evaluation.
    max_scope_limit : float | None
        Override for the maximum permitted scope (from baseline config or settings).
        If None, uses DEFAULT_SCOPE_LIMITS or the input's max_scope_override.

    Returns
    -------
    AdaptivePolicyDecision
        Structured decision with full audit trail.
    """
    score = 0.0
    rule_ids: list[str] = []
    reasons: list[str] = []

    # ── Guard: missing required fields → fail closed ──────────────────────
    if not inp.agent_id or not inp.action_type or not inp.agent_role:
        return AdaptivePolicyDecision(
            outcome=PolicyOutcome.DENY,
            confidence=0.0,
            risk_level=RiskLevel.CRITICAL,
            allowed_scope=0.0,
            capability_ttl_seconds=0,
            requires_human_approval=False,
            approval_reason=None,
            rule_ids=["MISSING_REQUIRED_CONTEXT"],
            explanation=(
                "Required context fields are missing (agent_id, action_type, or role). "
                "Request denied by fail-closed policy."
            ),
            policy_version=inp.policy_version,
        )

    # ── Guard: suspicious activity — never increase trust ─────────────────
    if inp.recent_failures < 0:
        inp = AdaptivePolicyInput(**{**inp.__dict__, "recent_failures": 0})

    # ── Rule 1: Trusted role bonus ────────────────────────────────────────
    role_bonus = TRUSTED_ROLES.get(inp.agent_role, 0.0)
    if role_bonus > 0:
        score += role_bonus
        rule_ids.append("R1_TRUSTED_ROLE")
        reasons.append(
            f"Role {inp.agent_role!r} contributes +{role_bonus:.2f} trust."
        )
    else:
        rule_ids.append("R1_UNKNOWN_ROLE")
        reasons.append(
            f"Role {inp.agent_role!r} is not a recognized trusted role (+0.00)."
        )

    # ── Rule 2: Permitted action ──────────────────────────────────────────
    permitted_upper = [a.upper() for a in inp.permitted_actions]
    if inp.action_type.upper() in permitted_upper:
        score += 0.20
        rule_ids.append("R2_ACTION_PERMITTED")
        reasons.append(
            f"Action {inp.action_type!r} is in agent's permitted set (+0.20)."
        )
    else:
        # Not permitted — hard deny regardless of other scores
        return AdaptivePolicyDecision(
            outcome=PolicyOutcome.DENY,
            confidence=0.0,
            risk_level=RiskLevel.CRITICAL,
            allowed_scope=0.0,
            capability_ttl_seconds=0,
            requires_human_approval=False,
            approval_reason=None,
            rule_ids=["R2_ACTION_NOT_PERMITTED"],
            explanation=(
                f"Action {inp.action_type!r} is not in the agent's permitted "
                f"action set {inp.permitted_actions!r}. Request denied."
            ),
            policy_version=inp.policy_version,
        )

    # ── Rule 3: Scope check ───────────────────────────────────────────────
    effective_max_scope = (
        max_scope_limit
        or inp.max_scope_override
        or DEFAULT_SCOPE_LIMITS.get(inp.action_type.upper(), float("inf"))
    )
    scope_ok = inp.requested_scope <= effective_max_scope
    if scope_ok:
        if inp.requested_scope > 0:
            score += 0.15
            rule_ids.append("R3_SCOPE_WITHIN_LIMIT")
            reasons.append(
                f"Requested scope {inp.requested_scope} ≤ max {effective_max_scope} (+0.15)."
            )
        else:
            # No scope requested (e.g., email with no amount) — neutral
            rule_ids.append("R3_SCOPE_NOT_APPLICABLE")
            reasons.append("Scope not applicable for this action type (±0.00).")
    else:
        # Scope exceeds limit — hard deny
        return AdaptivePolicyDecision(
            outcome=PolicyOutcome.DENY,
            confidence=0.0,
            risk_level=RiskLevel.CRITICAL,
            allowed_scope=0.0,
            capability_ttl_seconds=0,
            requires_human_approval=False,
            approval_reason=None,
            rule_ids=["R3_SCOPE_EXCEEDED"],
            explanation=(
                f"Requested scope {inp.requested_scope} exceeds the maximum "
                f"permitted scope of {effective_max_scope}. Request denied."
            ),
            policy_version=inp.policy_version,
        )

    # ── Rule 4: Context validation ────────────────────────────────────────
    if inp.context_valid:
        score += 0.15
        rule_ids.append("R4_CONTEXT_VALID")
        reasons.append(f"Context validation passed: {inp.context_reason} (+0.15).")
    else:
        score -= 0.40
        rule_ids.append("R4_CONTEXT_INVALID")
        reasons.append(
            f"Context validation FAILED: {inp.context_reason} (-0.40). "
            "Missing or contradictory security context."
        )

    # ── Rule 5: Action sensitivity ────────────────────────────────────────
    sensitivity = ACTION_SENSITIVITY.get(inp.action_type.upper(), "MEDIUM")
    if sensitivity == "LOW":
        score += 0.10
        rule_ids.append("R5_LOW_SENSITIVITY")
        reasons.append(f"Action {inp.action_type!r} has LOW sensitivity (+0.10).")
    elif sensitivity == "HIGH":
        score -= 0.20
        rule_ids.append("R5_HIGH_SENSITIVITY")
        reasons.append(
            f"Action {inp.action_type!r} has HIGH sensitivity (-0.20). "
            "Stricter controls applied."
        )
    else:
        rule_ids.append("R5_MEDIUM_SENSITIVITY")
        reasons.append(
            f"Action {inp.action_type!r} has MEDIUM sensitivity (±0.00)."
        )

    # ── Rule 6: Suspicious activity / recent failures ─────────────────────
    if inp.suspicious_activity:
        score -= 0.30
        rule_ids.append("R6_SUSPICIOUS_ACTIVITY")
        reasons.append(
            "Suspicious activity flag is set (-0.30). "
            "Trust cannot be increased under suspicious conditions."
        )
    elif inp.recent_failures >= 5:
        score -= 0.20
        rule_ids.append("R6_HIGH_FAILURE_RATE")
        reasons.append(
            f"{inp.recent_failures} recent failures detected (-0.20). "
            "Elevated caution applied."
        )
    elif inp.recent_failures >= 2:
        score -= 0.10
        rule_ids.append("R6_MODERATE_FAILURE_RATE")
        reasons.append(
            f"{inp.recent_failures} recent failures detected (-0.10)."
        )

    # ── Clamp score to [0.0, 1.0] ─────────────────────────────────────────
    score = max(0.0, min(1.0, score))
    score = round(score, 4)

    # ── Classify risk ─────────────────────────────────────────────────────
    if score >= 0.70:
        risk = RiskLevel.LOW
    elif score >= 0.40:
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.HIGH

    # ── Determine outcome ─────────────────────────────────────────────────
    # Hard deny if score is 0 (context failed + no recovery)
    if score == 0.0:
        return AdaptivePolicyDecision(
            outcome=PolicyOutcome.DENY,
            confidence=0.0,
            risk_level=RiskLevel.CRITICAL,
            allowed_scope=0.0,
            capability_ttl_seconds=0,
            requires_human_approval=False,
            approval_reason=None,
            rule_ids=rule_ids + ["SCORE_ZERO_HARD_DENY"],
            explanation=(
                "Confidence score is 0.0 after all penalties. "
                "Request denied (fail-closed). Reasons: "
                + " | ".join(reasons)
            ),
            policy_version=inp.policy_version,
        )

    # ── Compute adaptive scope and TTL ────────────────────────────────────
    # Scale allowed scope by confidence (low confidence = narrower scope)
    if effective_max_scope < float("inf") and inp.requested_scope > 0:
        # Confidence-weighted scope cap
        adaptive_scope_cap = effective_max_scope * score
        allowed_scope = min(inp.requested_scope, adaptive_scope_cap)
    else:
        allowed_scope = inp.requested_scope

    allowed_scope = round(allowed_scope, 2)

    # Scale TTL by confidence
    base_ttl = TTL_BY_RISK[risk]
    capability_ttl = max(30, int(base_ttl * score))  # At least 30 seconds

    # ── Determine approval requirement ────────────────────────────────────
    requires_approval = False
    approval_reason: Optional[str] = None

    if inp.action_type.upper() in ALWAYS_REQUIRES_APPROVAL:
        requires_approval = True
        approval_reason = (
            f"Action type {inp.action_type!r} always requires human approval."
        )
    elif score < MIN_CONFIDENCE_AUTO_APPROVE:
        requires_approval = True
        approval_reason = (
            f"Confidence score {score:.4f} is below the auto-approval threshold "
            f"of {MIN_CONFIDENCE_AUTO_APPROVE}. Human approval required."
        )
    elif risk == RiskLevel.HIGH and sensitivity == "HIGH":
        requires_approval = True
        approval_reason = (
            "High-risk, high-sensitivity action with subthreshold confidence "
            "requires human approval."
        )

    outcome = (
        PolicyOutcome.REQUIRE_APPROVAL if requires_approval else PolicyOutcome.ALLOW
    )

    # ── Build explanation ─────────────────────────────────────────────────
    explanation_parts = [
        f"Confidence score: {score:.4f} → Risk: {risk.value}.",
        f"Allowed scope: {allowed_scope} (requested: {inp.requested_scope}, max: {effective_max_scope}).",
        f"Capability TTL: {capability_ttl}s.",
        f"Outcome: {outcome.value}.",
    ]
    if requires_approval:
        explanation_parts.append(f"Approval required: {approval_reason}")
    explanation_parts.extend(reasons)

    return AdaptivePolicyDecision(
        outcome=outcome,
        confidence=score,
        risk_level=risk,
        allowed_scope=allowed_scope,
        capability_ttl_seconds=capability_ttl,
        requires_human_approval=requires_approval,
        approval_reason=approval_reason,
        rule_ids=rule_ids,
        explanation=" | ".join(explanation_parts),
        policy_version=inp.policy_version,
    )


# ── Convenience function for the gateway API ──────────────────────────────


def evaluate_for_request(
    agent_id: str,
    agent_role: str,
    permitted_actions: list[str],
    action_type: str,
    requested_scope: float,
    context_valid: bool,
    context_reason: str,
    recent_failures: int = 0,
    suspicious_activity: bool = False,
    max_scope_override: Optional[float] = None,
    policy_version: str = "v1",
) -> AdaptivePolicyDecision:
    """Convenience wrapper for constructing AdaptivePolicyInput inline."""
    inp = AdaptivePolicyInput(
        agent_id=agent_id,
        agent_role=agent_role,
        permitted_actions=permitted_actions,
        action_type=action_type,
        requested_scope=requested_scope,
        context_valid=context_valid,
        context_reason=context_reason,
        recent_failures=recent_failures,
        suspicious_activity=suspicious_activity,
        max_scope_override=max_scope_override,
        policy_version=policy_version,
    )
    return evaluate_adaptive_policy(inp)
