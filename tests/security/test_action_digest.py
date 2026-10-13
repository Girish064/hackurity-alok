"""Tests for Component A — Action Digest Calculation (`action_digest.py`)."""

from __future__ import annotations

import copy
import hashlib

import pytest

from app.security.action_digest import (
    ACTION_DIGEST_DOMAIN_SEPARATOR,
    STANDARD_TEST_VECTORS,
    calculate_action_digest,
    verify_action_digest,
)
from app.security.canonicalization import canonicalize_action


@pytest.fixture
def base_action() -> dict:
    return {
        "schema_version": "1",
        "tenant_id": "tenant-001",
        "principal_id": "agent-007",
        "tool": "refund",
        "resource": "order-123",
        "arguments": {
            "amount_minor": 50000,
            "currency": "INR",
        },
        "environment": "demo",
        "policy_version": "policy-v1",
        "intent_id": "intent-001",
    }


def test_identical_actions_produce_identical_digests(base_action: dict) -> None:
    """Authorization and execution computing digests over identical semantic actions produce identical hashes."""
    reordered_json = """
    {
      "intent_id": "intent-001",
      "policy_version": "policy-v1",
      "environment": "demo",
      "arguments": {
        "currency": "INR",
        "amount_minor": 50000
      },
      "resource": "order-123",
      "tool": "refund",
      "principal_id": "agent-007",
      "tenant_id": "tenant-001",
      "schema_version": 1
    }
    """
    gateway_digest = calculate_action_digest(base_action)
    executor_digest = calculate_action_digest(reordered_json)
    assert gateway_digest == executor_digest
    assert len(gateway_digest) == 64
    assert verify_action_digest(base_action, executor_digest) is True


def test_domain_separated_sha256_construction(base_action: dict) -> None:
    """Verify exact SHA256(b'AGENTSHIELD-ACTION-V1\\x00' + canonical_bytes) formula."""
    canonical_bytes = canonicalize_action(base_action)
    expected = hashlib.sha256(ACTION_DIGEST_DOMAIN_SEPARATOR + canonical_bytes).hexdigest()
    assert calculate_action_digest(base_action) == expected


@pytest.mark.parametrize(
    "field_mutator",
    [
        lambda a: a["arguments"].__setitem__("amount_minor", 500000),  # ₹500 -> ₹5,000
        lambda a: a.__setitem__("resource", "order-999"),
        lambda a: a.__setitem__("tenant_id", "tenant-002"),
        lambda a: a.__setitem__("tool", "payout"),
        lambda a: a.__setitem__("environment", "production"),
        lambda a: a.__setitem__("principal_id", "agent-008"),
        lambda a: a.__setitem__("intent_id", "intent-002"),
        lambda a: a.__setitem__("policy_version", "policy-v2"),
    ],
)
def test_changing_any_security_sensitive_field_changes_digest(
    base_action: dict, field_mutator
) -> None:
    """Mutating amount, resource, tenant, tool, environment, principal, intent, or policy version changes the digest."""
    original_digest = calculate_action_digest(base_action)
    mutated = copy.deepcopy(base_action)
    field_mutator(mutated)
    mutated_digest = calculate_action_digest(mutated)
    assert mutated_digest != original_digest
    assert verify_action_digest(mutated, original_digest) is False


def test_standard_shared_test_vectors() -> None:
    """Verify all shared cross-component test vectors match their canonical JSON and digests."""
    for vec in STANDARD_TEST_VECTORS:
        canonical_bytes = canonicalize_action(vec["action"])
        assert canonical_bytes.decode("utf-8") == vec["canonical_json"]
        expected_digest = hashlib.sha256(
            b"AGENTSHIELD-ACTION-V1\x00" + vec["canonical_json"].encode("utf-8")
        ).hexdigest()
        assert calculate_action_digest(vec["action"]) == expected_digest
