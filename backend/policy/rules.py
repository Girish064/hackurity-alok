"""
backend/policy/rules.py
Deterministic policy rule definitions.

These are Python data structures, not an LLM or ML system.
Hard DENY decisions cannot be overridden by any external scoring system.

Structure:
  RULES is a list of dicts evaluated top-to-bottom.
  The first matching rule wins.
  If no rule matches, the default decision is DENY (fail-closed).

Fields per rule:
  action_type          : str            — exact match
  tenant_id            : str | None     — None = any tenant
  required_permission  : str | None     — None = no permission check
  max_amount           : float | None   — None = no amount limit
  requires_approval_above: float | None — None = never require approval
  decision             : Decision       — base decision if conditions met
  reason               : str
"""
from __future__ import annotations

from backend.policy.models import Decision

# ──────────────────────────────────────────────────────────────────────────
# Default rule table — shared across all tenants in the demo.
# In production, rules would be loaded from the `policies` DB table.
# ──────────────────────────────────────────────────────────────────────────
DEFAULT_RULES: list[dict] = [
    {
        # Support agents may issue refunds up to ₹1000 without approval;
        # above ₹1000 and up to ₹10000 requires human approval;
        # above ₹10000 is hard-denied.
        "action_type": "ISSUE_REFUND",
        "required_permission": "ISSUE_REFUND",
        "max_amount": 10_000.00,          # hard deny above this
        "requires_approval_above": 1_000.00,
        "decision": Decision.ALLOW,
        "reason": (
            "Refund authorized. Amounts above ₹1000 require human approval; "
            "amounts above ₹10000 are hard-denied."
        ),
    },
    {
        # Agents with SEND_EMAIL permission can send email without approval.
        "action_type": "SEND_EMAIL",
        "required_permission": "SEND_EMAIL",
        "max_amount": None,
        "requires_approval_above": None,
        "decision": Decision.ALLOW,
        "reason": "Email send authorized.",
    },
    # Catch-all: deny everything else
    {
        "action_type": "*",
        "required_permission": None,
        "max_amount": None,
        "requires_approval_above": None,
        "decision": Decision.DENY,
        "reason": "No matching policy rule. Request denied by default.",
    },
]
