"""Tests for Component D — Signed Execution Receipts (`execution_receipt.py`)."""

from __future__ import annotations

import copy

import pytest

from app.security.action_digest import calculate_action_digest
from app.security.execution_receipt import (
    ExecutionResultStatus,
    ReceiptVerificationError,
    sign_execution_receipt,
    verify_execution_receipt,
)
from app.security.key_management import KeyPurpose, ManagedKey, create_default_key_manager


@pytest.fixture
def sample_action() -> dict:
    return {
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
    }


@pytest.mark.parametrize(
    "outcome_status",
    [
        ExecutionResultStatus.SUCCEEDED,
        ExecutionResultStatus.FAILED_FINAL,
        ExecutionResultStatus.UNKNOWN,
    ],
)
def test_sign_and_independently_verify_receipt_outcomes(
    sample_action: dict, outcome_status: ExecutionResultStatus
) -> None:
    """Receipts distinguish SUCCEEDED, FAILED_FINAL, and UNKNOWN and verify with public keys."""
    key_mgr = create_default_key_manager()
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)
    digest = calculate_action_digest(sample_action)

    signed = sign_execution_receipt(
        {
            "receipt_id": "rcpt-001",
            "execution_id": "exec-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": "cap-001",
            "approval_id": "appr-001",
            "execution_result": outcome_status,
            "timestamp": 1700000050,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    # Verify using public-only verifier store (no private keys)
    res = verify_execution_receipt(
        signed.to_dict(),
        key_manager=key_mgr.public_verifier_store(),
        expected_action=sample_action,
    )
    assert res.valid is True
    assert res.execution_result == outcome_status.value


def test_tampered_receipt_fails_signature_verification(sample_action: dict) -> None:
    """Modifying any field of a signed receipt causes signature verification to fail."""
    key_mgr = create_default_key_manager()
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)

    signed = sign_execution_receipt(
        {
            "receipt_id": "rcpt-001",
            "execution_id": "exec-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-001",
            "execution_result": ExecutionResultStatus.FAILED_FINAL,
            "timestamp": 1700000050,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    tampered = signed.to_dict()
    tampered["execution_result"] = "SUCCEEDED"

    with pytest.raises(ReceiptVerificationError) as exc_info:
        verify_execution_receipt(
            tampered,
            key_manager=key_mgr.public_verifier_store(),
        )
    assert exc_info.value.error_code == "INVALID_RECEIPT_SIGNATURE"


def test_receipt_presented_for_another_action_rejected(sample_action: dict) -> None:
    """A valid receipt for one action is rejected when presented as evidence for another action."""
    key_mgr = create_default_key_manager()
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)

    signed = sign_execution_receipt(
        {
            "receipt_id": "rcpt-001",
            "execution_id": "exec-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-001",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000050,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    different_action = copy.deepcopy(sample_action)
    different_action["arguments"]["amount_minor"] = 99900

    with pytest.raises(ReceiptVerificationError) as exc_info:
        verify_execution_receipt(
            signed,
            key_manager=key_mgr.public_verifier_store(),
            expected_action=different_action,
        )
    assert exc_info.value.error_code == "RECEIPT_ACTION_MISMATCH"


def test_reject_unknown_or_wrong_purpose_signing_key(sample_action: dict) -> None:
    """Receipts cannot be signed with a capability key or an unknown key."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)

    with pytest.raises(ReceiptVerificationError) as exc_info:
        sign_execution_receipt(
            {
                "receipt_id": "rcpt-001",
                "execution_id": "exec-001",
                "tenant_id": "tenant-demo",
                "principal_id": "agent-support-01",
                "action": sample_action,
                "capability_id": "cap-001",
                "execution_result": ExecutionResultStatus.SUCCEEDED,
                "timestamp": 1700000050,
                "executor_id": "executor-01",
            },
            cap_key,
        )
    assert exc_info.value.error_code == "KEY_PURPOSE_MISMATCH"

    unknown_key = ManagedKey.generate("key-unknown-rcpt", purpose=KeyPurpose.RECEIPT, created_at=1700000000)
    signed_unknown = sign_execution_receipt(
        {
            "receipt_id": "rcpt-001",
            "execution_id": "exec-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-001",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000050,
            "executor_id": "executor-01",
        },
        unknown_key,
    )
    with pytest.raises(ReceiptVerificationError) as exc_info2:
        verify_execution_receipt(
            signed_unknown,
            key_manager=key_mgr.public_verifier_store(),
        )
    assert exc_info2.value.error_code == "UNKNOWN_SIGNING_KEY"
