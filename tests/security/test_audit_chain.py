"""Tests for Component E — Tamper-Evident Audit Chain (`audit_chain.py`)."""

from __future__ import annotations

import copy

import pytest

from app.security.action_digest import calculate_action_digest
from app.security.audit_chain import (
    AuditChain,
    append_audit_record,
    create_chain_checkpoint,
    reset_default_audit_chain,
    verify_audit_chain,
)
from app.security.key_management import KeyPurpose, create_default_key_manager


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


def _build_three_record_chain(sample_action: dict) -> tuple[list[dict], object]:
    key_mgr = create_default_key_manager()
    audit_key = key_mgr.get_signing_key(purpose=KeyPurpose.AUDIT)
    chain = AuditChain(signing_key=audit_key)
    digest = calculate_action_digest(sample_action)

    r1 = append_audit_record(
        {
            "event_id": "evt-001",
            "timestamp": 1700000010,
            "event_type": "ACTION_AUTHORIZED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": "cap-001",
            "details": {"policy_decision": "ALLOW"},
        },
        chain=chain,
    )
    r2 = append_audit_record(
        {
            "event_id": "evt-002",
            "timestamp": 1700000020,
            "event_type": "CAPABILITY_CLAIMED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": "cap-001",
            "execution_id": "exec-001",
            "details": {"state": "CLAIMED"},
        },
        chain=chain,
    )
    r3 = append_audit_record(
        {
            "event_id": "evt-003",
            "timestamp": 1700000030,
            "event_type": "EXECUTION_SUCCEEDED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": "cap-001",
            "execution_id": "exec-001",
            "receipt_id": "rcpt-001",
            "details": {"amount_minor": 50000},
        },
        chain=chain,
    )
    return [r1.to_dict(), r2.to_dict(), r3.to_dict()], key_mgr


def test_valid_audit_chain_verification(sample_action: dict) -> None:
    """Valid hash-chained and Ed25519-signed audit records pass independent verification."""
    records, key_mgr = _build_three_record_chain(sample_action)
    report = verify_audit_chain(records, key_manager=key_mgr.public_verifier_store())
    assert report.valid is True
    assert report.total_records == 3
    assert report.verified_records == 3
    assert report.head_sequence_number == 3


def test_detect_modified_audit_record_a10(sample_action: dict) -> None:
    """A10: Modifying an existing audit record is detected by `verify_audit_chain`."""
    records, key_mgr = _build_three_record_chain(sample_action)
    tampered = copy.deepcopy(records)
    tampered[1]["details"]["state"] = "BYPASSED"

    report = verify_audit_chain(tampered, key_manager=key_mgr.public_verifier_store())
    assert report.valid is False
    assert report.error_code == "RECORD_HASH_MISMATCH"
    assert report.first_invalid_sequence == 2


def test_detect_deleted_audit_record_a10(sample_action: dict) -> None:
    """A10: Deleting an intermediate audit record breaks sequence continuity and prev_hash links."""
    records, key_mgr = _build_three_record_chain(sample_action)
    deleted = [records[0], records[2]]  # Record 2 deleted

    report = verify_audit_chain(deleted, key_manager=key_mgr.public_verifier_store())
    assert report.valid is False
    error_codes = {issue.error_code for issue in report.issues}
    assert "SEQUENCE_DISCONTINUITY" in error_codes
    assert "PREV_HASH_MISMATCH" in error_codes


def test_detect_reordered_audit_records_a10(sample_action: dict) -> None:
    """A10: Swapping the order of audit records is detected by `verify_audit_chain`."""
    records, key_mgr = _build_three_record_chain(sample_action)
    reordered = [records[0], records[2], records[1]]

    report = verify_audit_chain(reordered, key_manager=key_mgr.public_verifier_store())
    assert report.valid is False
    error_codes = {issue.error_code for issue in report.issues}
    assert "SEQUENCE_DISCONTINUITY" in error_codes
    assert "PREV_HASH_MISMATCH" in error_codes


def test_detect_tail_truncation_via_signed_checkpoint(sample_action: dict) -> None:
    """Signed chain-head checkpoint detects tail truncation or whole-chain deletion."""
    records, key_mgr = _build_three_record_chain(sample_action)
    audit_key = key_mgr.get_signing_key(purpose=KeyPurpose.AUDIT)
    checkpoint = create_chain_checkpoint(records, signing_key=audit_key, timestamp=1700000035)

    # Valid against full 3-record chain
    valid_report = verify_audit_chain(
        records,
        key_manager=key_mgr.public_verifier_store(),
        expected_checkpoint=checkpoint,
    )
    assert valid_report.valid is True

    # Tail truncation: attacker deletes record 3 (tail of chain)
    truncated = records[:2]
    trunc_report = verify_audit_chain(
        truncated,
        key_manager=key_mgr.public_verifier_store(),
        expected_checkpoint=checkpoint,
    )
    assert trunc_report.valid is False
    assert trunc_report.error_code == "AUDIT_CHAIN_TRUNCATED"

    # Whole-chain deletion: attacker deletes all records
    empty_report = verify_audit_chain(
        [],
        key_manager=key_mgr.public_verifier_store(),
        expected_checkpoint=checkpoint,
    )
    assert empty_report.valid is False
    assert empty_report.error_code == "AUDIT_CHAIN_TRUNCATED"


def test_default_audit_chain_convenience_interface(sample_action: dict) -> None:
    """Verify standalone `append_audit_record(event)` works seamlessly with `verify_audit_chain`."""
    reset_default_audit_chain()
    r1 = append_audit_record(
        {
            "event_id": "evt-def-1",
            "timestamp": 1700000100,
            "event_type": "ACTION_AUTHORIZED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
        }
    )
    r2 = append_audit_record(
        {
            "event_id": "evt-def-2",
            "timestamp": 1700000105,
            "event_type": "EXECUTION_SUCCEEDED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": sample_action,
        }
    )
    report = verify_audit_chain([r1, r2])
    assert report.valid is True
    assert report.total_records == 2
