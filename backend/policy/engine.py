"""
backend/policy/engine.py
Deterministic policy evaluation engine.

Security guarantee: Hard DENY decisions are final.
No LLM output, risk score or external signal can override a DENY.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation

from backend.policy.models import Decision, PolicyDecision
from backend.policy.rules import DEFAULT_RULES
from backend.storage.models.agent import Agent


def _extract_amount(parameters: dict) -> Decimal | None:
    """
    Try to extract a numeric amount from the parameters dict.
    Amounts must be strings (e.g. "500.00") per the canonicalization contract.
    Returns None if no amount field is present or if parsing fails.
    """
    raw = parameters.get("amount")
    if raw is None:
        return None
    try:
        return Decimal(str(raw))
    except InvalidOperation:
        return None


def evaluate(agent: Agent, action_type: str, parameters: dict) -> PolicyDecision:
    """
    Evaluate the policy rules for the given agent and action.

    Returns a PolicyDecision with ALLOW, DENY, or REQUIRE_APPROVAL.
    A DENY result must never be overridden downstream.

    Parameters
    ----------
    agent       : Agent ORM object (loaded from DB by the gateway)
    action_type : Action type string, e.g. "ISSUE_REFUND"
    parameters  : Action parameters dict from the request body
    """
    amount = _extract_amount(parameters)
    agent_permissions: list[str] = agent.permissions or []
    agent_max_refund: Decimal | None = (
        Decimal(str(agent.max_refund_amount))
        if agent.max_refund_amount is not None
        else None
    )

    for rule in DEFAULT_RULES:
        rule_action = rule["action_type"]
        # Match action_type: exact or wildcard
        if rule_action != "*" and rule_action != action_type:
            continue

        # Permission check
        required_perm = rule.get("required_permission")
        if required_perm and required_perm not in agent_permissions:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=(
                    f"Agent does not have the required permission: "
                    f"{required_perm!r}. Request denied."
                ),
            )

        rule_max: float | None = rule.get("max_amount")
        rule_approval_above: float | None = rule.get("requires_approval_above")

        # Amount-based checks (only when rule has amount constraints)
        if amount is not None and rule_max is not None:
            rule_max_dec = Decimal(str(rule_max))

            # Agent-level cap (per-agent policy, more restrictive than rule)
            if agent_max_refund is not None and amount > agent_max_refund:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=(
                        f"Amount {amount} exceeds this agent's configured limit "
                        f"of {agent_max_refund}. Request hard-denied."
                    ),
                )

            # Hard deny above rule max
            if amount > rule_max_dec:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=(
                        f"Amount {amount} exceeds the hard limit of "
                        f"{rule_max_dec}. Request hard-denied."
                    ),
                )

            # Approval required above threshold
            if rule_approval_above is not None:
                approval_threshold = Decimal(str(rule_approval_above))
                if amount > approval_threshold:
                    return PolicyDecision(
                        decision=Decision.REQUIRE_APPROVAL,
                        reason=(
                            f"Amount {amount} exceeds the approval threshold of "
                            f"{approval_threshold}. Human approval required."
                        ),
                        approval_threshold=float(approval_threshold),
                    )

        # Rule matches — return its base decision
        return PolicyDecision(
            decision=rule["decision"],
            reason=rule["reason"],
        )

    # Fallback — should never reach here because of the wildcard rule, but
    # fail closed if it does.
    return PolicyDecision(
        decision=Decision.DENY,
        reason="No policy rule matched. Request denied by default (fail-closed).",
    )
