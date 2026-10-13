"""
tests/unit/test_policy.py
Unit tests for the policy engine.
Tests run without database or Redis — pure function evaluation.
"""
from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from backend.policy.engine import evaluate
from backend.policy.models import Decision


def make_agent(permissions=None, max_refund=None):
    agent = MagicMock()
    agent.permissions = permissions or []
    agent.max_refund_amount = max_refund
    return agent


class TestRefundPolicy:
    def test_authorized_refund_within_limit(self):
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=2000)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "500.00"})
        assert result.decision == Decision.ALLOW

    def test_refund_requires_approval_above_threshold(self):
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=5000)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "1500.00"})
        assert result.decision == Decision.REQUIRE_APPROVAL
        assert result.approval_threshold == 1000.0

    def test_refund_hard_denied_above_max(self):
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=50000)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "15000.00"})
        assert result.decision == Decision.DENY

    def test_agent_without_refund_permission_denied(self):
        agent = make_agent(permissions=[], max_refund=None)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "100.00"})
        assert result.decision == Decision.DENY
        assert "permission" in result.reason.lower()

    def test_agent_max_refund_cap_enforced(self):
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=300)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "400.00"})
        assert result.decision == Decision.DENY

    def test_unknown_action_type_denied(self):
        agent = make_agent(permissions=["ISSUE_REFUND"])
        result = evaluate(agent, "WIRE_TRANSFER", {"amount": "100.00"})
        assert result.decision == Decision.DENY

    def test_deny_cannot_be_overridden(self):
        """Regression: ensure no code path returns ALLOW after a DENY."""
        agent = make_agent(permissions=[])
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "500.00"})
        assert result.decision == Decision.DENY
        # Simulate an LLM "override" — the engine must not accept it
        assert result.decision != Decision.ALLOW

    def test_boundary_exactly_at_threshold(self):
        """Exactly at the threshold: ALLOW (not REQUIRE_APPROVAL)."""
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=5000)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "1000.00"})
        assert result.decision == Decision.ALLOW

    def test_boundary_one_above_threshold(self):
        """One rupee above: REQUIRE_APPROVAL."""
        agent = make_agent(permissions=["ISSUE_REFUND"], max_refund=5000)
        result = evaluate(agent, "ISSUE_REFUND", {"amount": "1000.01"})
        assert result.decision == Decision.REQUIRE_APPROVAL
