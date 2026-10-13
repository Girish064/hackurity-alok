"""
tests/unit/test_receipts.py
Unit tests for execution receipt signing and verification using Ed25519.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import sign_execution_receipt, verify_execution_receipt
from security.exceptions import ReceiptVerificationError


@pytest.fixture(scope="module")
def key_pair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


class TestExecutionReceipts:
    def test_sign_and_verify_receipt_success(self, key_pair):
        priv, pub = key_pair
        token = sign_execution_receipt(
            capability_id="cap-001",
            action_digest="digest-12345",
            executor_id="executor-v1",
            outcome="SUCCESS",
            outcome_data={"refund_id": "ref-001", "amount": 500.0},
            executed_at="2026-10-13T10:00:00+00:00",
            signing_key=priv,
            key_id="key-v1",
        )
        assert isinstance(token, str)

        claims = verify_execution_receipt(token, pub)
        assert claims.capability_id == "cap-001"
        assert claims.action_digest == "digest-12345"
        assert claims.executor_id == "executor-v1"
        assert claims.outcome == "SUCCESS"
        assert claims.outcome_data["refund_id"] == "ref-001"

    def test_receipt_wrong_public_key_rejected(self, key_pair):
        priv, _ = key_pair
        wrong_pub = Ed25519PrivateKey.generate().public_key()
        token = sign_execution_receipt(
            capability_id="cap-002",
            action_digest="digest-12345",
            executor_id="executor-v1",
            outcome="SUCCESS",
            outcome_data={},
            executed_at="2026-10-13T10:00:00+00:00",
            signing_key=priv,
            key_id="key-v1",
        )
        with pytest.raises(ReceiptVerificationError):
            verify_execution_receipt(token, wrong_pub)

    def test_tampered_receipt_token_rejected(self, key_pair):
        _, pub = key_pair
        with pytest.raises(ReceiptVerificationError):
            verify_execution_receipt("invalid.receipt.token", pub)
