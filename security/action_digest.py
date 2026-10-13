"""Component A — Deterministic Action Digest Calculation for AgentShield V2.

Implements the agreed domain-separated SHA-256 construction:
    action_hash = SHA256(b"AGENTSHIELD-ACTION-V1\\x00" + canonical_bytes)
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping, Union

from .canonicalization import (
    CanonicalAction,
    CanonicalizationError,
    canonicalize_action,
)

ACTION_DIGEST_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-ACTION-V1\x00"
DIGEST_VERSION: str = "AGENTSHIELD-ACTION-V1"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def is_valid_sha256_hex(digest: Any) -> bool:
    """Return True if digest is a 64-character lowercase hexadecimal SHA-256 string."""
    return isinstance(digest, str) and bool(_HEX64_RE.match(digest))


def calculate_action_digest_bytes(
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes, bytearray],
) -> bytes:
    """Calculate the 32-byte raw SHA-256 digest over domain separator + canonical action bytes."""
    canonical_bytes = canonicalize_action(action)
    hasher = hashlib.sha256()
    hasher.update(ACTION_DIGEST_DOMAIN_SEPARATOR)
    hasher.update(canonical_bytes)
    return hasher.digest()


def calculate_action_digest(
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes, bytearray],
) -> str:
    """Calculate the 64-character lowercase hex SHA-256 action digest."""
    return calculate_action_digest_bytes(action).hex()


def verify_action_digest(
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes, bytearray],
    expected_digest: str,
) -> bool:
    """Constant-time verification that an action matches the expected SHA-256 hex digest."""
    if not is_valid_sha256_hex(expected_digest):
        return False
    try:
        computed = calculate_action_digest(action)
    except CanonicalizationError:
        return False
    return hmac.compare_digest(computed, expected_digest)


# Shared deterministic test vectors for cross-component verification
STANDARD_TEST_VECTORS: tuple[dict[str, Any], ...] = (
    {
        "name": "master_spec_refund_v1",
        "action": {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": "orders/ORDER-123",
            "arguments": {
                "order_id": "ORDER-123",
                "amount_minor": 50000,
            },
            "environment": "demo",
            "policy_version": 3,
            "intent_id": "intent-demo-001",
        },
        "canonical_json": (
            '{"arguments":{"amount_minor":50000,"order_id":"ORDER-123"},'
            '"environment":"demo","intent_id":"intent-demo-001","policy_version":3,'
            '"principal_id":"agent-support-01","resource":"orders/ORDER-123",'
            '"schema_version":1,"tenant_id":"tenant-demo","tool":"issue_refund"}'
        ),
        "expected_digest": "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28",
    },
    {
        "name": "girish_spec_refund_v1",
        "action": {
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
        },
        "canonical_json": (
            '{"arguments":{"amount_minor":50000,"currency":"INR"},'
            '"environment":"demo","intent_id":"intent-001","policy_version":"policy-v1",'
            '"principal_id":"agent-007","resource":"order-123",'
            '"schema_version":1,"tenant_id":"tenant-001","tool":"refund"}'
        ),
    },
)
