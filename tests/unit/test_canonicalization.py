"""
tests/unit/test_canonicalization.py
Unit tests for action canonicalization and digest calculation.

These tests verify the determinism and domain-separation properties.
Girish may add additional test vectors to this file.
"""
from __future__ import annotations

import pytest

from security import canonicalize_action, calculate_action_digest
from security.schemas import ActionRequest


def make_action(**kwargs) -> ActionRequest:
    defaults = {
        "agent_id": "agent-001",
        "tenant_id": "tenant-001",
        "action_type": "ISSUE_REFUND",
        "parameters": {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"},
        "request_id": "req-001",
        "submitted_at": "2026-10-13T10:00:00+00:00",
    }
    defaults.update(kwargs)
    return ActionRequest(**defaults)


class TestCanonicalization:
    def test_same_input_same_output(self):
        a = make_action()
        b = make_action()
        assert canonicalize_action(a) == canonicalize_action(b)

    def test_domain_prefix_present(self):
        a = make_action()
        canonical = canonicalize_action(a)
        assert canonical.startswith(b"agentshield-action-v1:")

    def test_different_amounts_different_bytes(self):
        a = make_action(parameters={"amount": "500.00", "currency": "INR", "order_id": "ORD-001"})
        b = make_action(parameters={"amount": "5000.00", "currency": "INR", "order_id": "ORD-001"})
        assert canonicalize_action(a) != canonicalize_action(b)

    def test_digest_is_64_hex_chars(self):
        a = make_action()
        digest = calculate_action_digest(canonicalize_action(a))
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_digest_is_deterministic(self):
        a = make_action()
        d1 = calculate_action_digest(canonicalize_action(a))
        d2 = calculate_action_digest(canonicalize_action(a))
        assert d1 == d2

    def test_parameter_key_order_does_not_matter(self):
        """Keys in parameters should be sorted, so order doesn't affect digest."""
        a = make_action(parameters={"amount": "500.00", "currency": "INR", "order_id": "ORD-001"})
        b = make_action(parameters={"order_id": "ORD-001", "currency": "INR", "amount": "500.00"})
        assert calculate_action_digest(canonicalize_action(a)) == calculate_action_digest(canonicalize_action(b))

    def test_changing_agent_id_changes_digest(self):
        a = make_action(agent_id="agent-001")
        b = make_action(agent_id="agent-002")
        assert calculate_action_digest(canonicalize_action(a)) != calculate_action_digest(canonicalize_action(b))

    def test_changing_tenant_id_changes_digest(self):
        a = make_action(tenant_id="tenant-001")
        b = make_action(tenant_id="tenant-002")
        assert calculate_action_digest(canonicalize_action(a)) != calculate_action_digest(canonicalize_action(b))
