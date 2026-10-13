"""Tests for Key Rotation, Revocation, and Historical Verification Policy (`key_management.py`)."""

from __future__ import annotations

import pytest

from app.security.audit_chain import AuditChain, append_audit_record, verify_audit_chain
from app.security.capability import (
    CapabilityVerificationError,
    ReplayProtectionStore,
    VerificationContext,
    issue_capability,
    verify_capability,
)
from app.security.execution_receipt import (
    ExecutionResultStatus,
    ReceiptVerificationError,
    sign_execution_receipt,
    verify_execution_receipt,
)
from app.security.key_management import (
    KeyPurpose,
    KeyStatus,
    RetiredKeyError,
    RevokedKeyError,
    create_default_key_manager,
)
from app.security.verification import verify_end_to_end_evidence


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


def test_historical_receipt_and_audit_verification_after_key_rotation(sample_action: dict) -> None:
    """Receipts and audit records signed before key retirement remain valid after planned key rotation."""
    key_mgr = create_default_key_manager(created_at=1700000000)
    old_rcpt_key = key_mgr.get_signing_key(kid="key-rcpt-2026-01", purpose=KeyPurpose.RECEIPT)
    old_audit_key = key_mgr.get_signing_key(kid="key-audit-2026-01", purpose=KeyPurpose.AUDIT)

    # Sign receipt and audit record at t=1700000100 with old keys
    receipt_v1 = sign_execution_receipt(
        {
            "receipt_id": "rcpt-hist-001",
            "execution_id": "exec-hist-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-hist-001",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000100,
            "executor_id": "executor-01",
        },
        old_rcpt_key,
    )

    chain = AuditChain(signing_key=old_audit_key)
    audit_r1 = append_audit_record(
        {
            "event_id": "evt-hist-001",
            "timestamp": 1700000100,
            "event_type": "EXECUTION_SUCCEEDED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-hist-001",
            "execution_id": "exec-hist-001",
            "receipt_id": "rcpt-hist-001",
        },
        chain=chain,
    )

    # Rotate keys at t=1700000500
    new_rcpt_key = key_mgr.rotate_key("key-rcpt-2026-01", "key-rcpt-2026-02", retired_at=1700000500)
    new_audit_key = key_mgr.rotate_key("key-audit-2026-01", "key-audit-2026-02", retired_at=1700000500)
    assert old_rcpt_key.status == KeyStatus.RETIRED
    assert new_rcpt_key.status == KeyStatus.ACTIVE

    # Append a second audit record with the new audit key at t=1700000600
    audit_r2 = append_audit_record(
        {
            "event_id": "evt-hist-002",
            "timestamp": 1700000600,
            "event_type": "AUDIT_KEY_ROTATED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "details": {"new_kid": new_audit_key.kid},
        },
        chain=chain,
        signing_key=new_audit_key,
    )

    # Historical verification of receipt_v1 and mixed-key audit chain succeeds
    rcpt_res = verify_execution_receipt(
        receipt_v1,
        key_manager=key_mgr.public_verifier_store(),
        expected_action=sample_action,
        allow_retired_keys=True,
    )
    assert rcpt_res.valid is True

    audit_report = verify_audit_chain(
        [audit_r1, audit_r2],
        key_manager=key_mgr.public_verifier_store(),
        allow_retired_keys=True,
    )
    assert audit_report.valid is True
    assert audit_report.verified_records == 2

    # End-to-end evidence bundle verification also succeeds across rotated keys
    e2e = verify_end_to_end_evidence(
        action=sample_action,
        signed_receipt=receipt_v1,
        audit_records=[audit_r1, audit_r2],
        key_manager=key_mgr,
    )
    assert e2e.valid is True


def test_retired_key_cannot_sign_new_artifacts_or_postdate_retirement(sample_action: dict) -> None:
    """A retired key cannot sign new artifacts, and artifacts claiming a timestamp after retirement are rejected."""
    key_mgr = create_default_key_manager(created_at=1700000000)
    rcpt_key = key_mgr.get_signing_key(kid="key-rcpt-2026-01", purpose=KeyPurpose.RECEIPT)

    # Sign a receipt claiming timestamp t=1700000900 BEFORE retiring the key at t=1700000500
    postdated_receipt = sign_execution_receipt(
        {
            "receipt_id": "rcpt-postdated",
            "execution_id": "exec-postdated",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-001",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000900,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    # Retire the key at t=1700000500
    key_mgr.retire_key("key-rcpt-2026-01", retired_at=1700000500)

    # Attempting to sign new data with a retired key raises RetiredKeyError
    with pytest.raises(RetiredKeyError):
        rcpt_key.sign(b"test")

    # Attempting to verify the postdated receipt (timestamp 1700000900 > retired_at 1700000500) fails
    with pytest.raises(ReceiptVerificationError) as exc_info:
        verify_execution_receipt(
            postdated_receipt,
            key_manager=key_mgr.public_verifier_store(),
            allow_retired_keys=True,
        )
    assert exc_info.value.error_code == "KEY_USED_AFTER_RETIREMENT"


def test_revoked_key_rejected_even_for_historical_records(sample_action: dict) -> None:
    """A key marked REVOKED (compromised) is rejected immediately for capabilities and receipts."""
    key_mgr = create_default_key_manager(created_at=1700000000)
    cap_key = key_mgr.get_signing_key(kid="key-cap-2026-01", purpose=KeyPurpose.CAPABILITY)
    rcpt_key = key_mgr.get_signing_key(kid="key-rcpt-2026-01", purpose=KeyPurpose.RECEIPT)

    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    receipt = sign_execution_receipt(
        {
            "receipt_id": "rcpt-001",
            "execution_id": "exec-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
            "capability_id": "cap-001",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000020,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    # Revoke both keys due to compromise
    key_mgr.revoke_key("key-cap-2026-01", revoked_at=1700000030)
    key_mgr.revoke_key("key-rcpt-2026-01", revoked_at=1700000030)

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000035,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "REVOKED_SIGNING_KEY"

    with pytest.raises(ReceiptVerificationError) as exc_info2:
        verify_execution_receipt(
            receipt,
            key_manager=key_mgr.public_verifier_store(),
            allow_retired_keys=True,
        )
    assert exc_info2.value.error_code == "REVOKED_SIGNING_KEY"


def test_private_key_never_leaked_in_repr_or_jwk() -> None:
    """Private key material must never appear in repr(), str(), or exported JWKs."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    raw_public_b64 = cap_key.public_jwk()["x"]

    assert "Private" not in repr(cap_key)
    assert "d" not in cap_key.public_jwk()  # 'd' is the JWK private key parameter
    assert cap_key.public_jwk()["x"] == raw_public_b64
