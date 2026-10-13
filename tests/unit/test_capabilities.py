"""
tests/unit/test_capabilities.py
Unit tests for capability issuance and verification using real Ed25519.
These tests use actual cryptographic operations — not mocks.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import (
    issue_capability,
    verify_capability,
    calculate_action_digest,
    canonicalize_action,
)
from security.exceptions import CapabilityExpiredError, CapabilityVerificationError
from security.schemas import ActionRequest


@pytest.fixture(scope="module")
def key_pair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture(scope="module")
def sample_digest():
    action = ActionRequest(
        agent_id="agent-001",
        tenant_id="tenant-001",
        action_type="ISSUE_REFUND",
        parameters={"amount": "500.00", "currency": "INR", "order_id": "ORD-001"},
        request_id="req-001",
        submitted_at="2026-10-13T10:00:00+00:00",
    )
    return calculate_action_digest(canonicalize_action(action))


class TestCapabilityIssuanceVerification:
    def test_valid_capability_verifies(self, key_pair, sample_digest):
        priv, pub = key_pair
        cap = issue_capability(
            agent_id="agent-001",
            tenant_id="tenant-001",
            action_digest=sample_digest,
            executor_id="executor-v1",
            ttl_seconds=300,
            approval_ref=None,
            signing_key=priv,
            key_id="key-v1",
        )
        claims = verify_capability(
            token=cap.token,
            expected_agent_id="agent-001",
            expected_tenant_id="tenant-001",
            expected_action_digest=sample_digest,
            expected_executor_id="executor-v1",
            verifying_key=pub,
        )
        assert claims.agent_id == "agent-001"
        assert claims.capability_id == cap.capability_id

    def test_tampered_digest_rejected(self, key_pair, sample_digest):
        priv, pub = key_pair
        cap = issue_capability(
            agent_id="agent-001",
            tenant_id="tenant-001",
            action_digest=sample_digest,
            executor_id="executor-v1",
            ttl_seconds=300,
            approval_ref=None,
            signing_key=priv,
            key_id="key-v1",
        )
        with pytest.raises(CapabilityVerificationError):
            verify_capability(
                token=cap.token,
                expected_agent_id="agent-001",
                expected_tenant_id="tenant-001",
                expected_action_digest="deadbeef" * 8,  # wrong digest
                expected_executor_id="executor-v1",
                verifying_key=pub,
            )

    def test_wrong_executor_rejected(self, key_pair, sample_digest):
        priv, pub = key_pair
        cap = issue_capability(
            agent_id="agent-001",
            tenant_id="tenant-001",
            action_digest=sample_digest,
            executor_id="executor-v1",
            ttl_seconds=300,
            approval_ref=None,
            signing_key=priv,
            key_id="key-v1",
        )
        with pytest.raises(CapabilityVerificationError):
            verify_capability(
                token=cap.token,
                expected_agent_id="agent-001",
                expected_tenant_id="tenant-001",
                expected_action_digest=sample_digest,
                expected_executor_id="executor-WRONG",
                verifying_key=pub,
            )

    def test_expired_capability_rejected(self, key_pair, sample_digest):
        priv, pub = key_pair
        cap = issue_capability(
            agent_id="agent-001",
            tenant_id="tenant-001",
            action_digest=sample_digest,
            executor_id="executor-v1",
            ttl_seconds=-1,  # Already expired
            approval_ref=None,
            signing_key=priv,
            key_id="key-v1",
        )
        with pytest.raises((CapabilityExpiredError, CapabilityVerificationError)):
            verify_capability(
                token=cap.token,
                expected_agent_id="agent-001",
                expected_tenant_id="tenant-001",
                expected_action_digest=sample_digest,
                expected_executor_id="executor-v1",
                verifying_key=pub,
            )

    def test_wrong_signing_key_rejected(self, sample_digest):
        priv1 = Ed25519PrivateKey.generate()
        priv2 = Ed25519PrivateKey.generate()
        pub2 = priv2.public_key()

        cap = issue_capability(
            agent_id="agent-001",
            tenant_id="tenant-001",
            action_digest=sample_digest,
            executor_id="executor-v1",
            ttl_seconds=300,
            approval_ref=None,
            signing_key=priv1,  # signed with key1
            key_id="key-v1",
        )
        with pytest.raises(CapabilityVerificationError):
            verify_capability(
                token=cap.token,
                expected_agent_id="agent-001",
                expected_tenant_id="tenant-001",
                expected_action_digest=sample_digest,
                expected_executor_id="executor-v1",
                verifying_key=pub2,  # verified with key2 → fails
            )
