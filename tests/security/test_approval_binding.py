"""Tests for Component C — Human Approval Binding (`approval_binding.py`)."""

from __future__ import annotations

import copy

import pytest

from app.security.action_digest import calculate_action_digest
from app.security.approval_binding import (
    ApprovalConsumptionStore,
    ApprovalDecision,
    ApprovalVerificationError,
    AuthenticatedApproverContext,
    create_approval_record,
    verify_approval,
)
from app.security.capability import (
    CapabilityVerificationError,
    ReplayProtectionStore,
    VerificationContext,
    issue_capability,
    verify_capability,
)
from app.security.key_management import KeyPurpose, create_default_key_manager


@pytest.fixture
def refund_500_action() -> dict:
    return {
        "schema_version": 1,
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "arguments": {
            "order_id": "ORDER-123",
            "amount_minor": 50000,  # ₹500.00 in paise
        },
        "environment": "demo",
        "policy_version": 3,
        "intent_id": "intent-demo-001",
    }


def test_valid_action_bound_approval_and_execution_b2(refund_500_action: dict) -> None:
    """B2: Approval-required operation succeeds once valid action-bound approval is provided and consumed."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    consumption_store = ApprovalConsumptionStore()

    approver = AuthenticatedApproverContext(
        approver_id="human-manager-alice",
        tenant_id="tenant-demo",
    )
    approval = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=approver,
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        approval_id="appr-demo-001",
        created_at=1700000010,
        expires_at=1700000310,
    )

    cap_token = issue_capability(
        {
            "action": refund_500_action,
            "approval_id": approval.approval_id,
            "iat": 1700000015,
            "exp": 1700000075,
        },
        cap_key,
    )

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        approval_consumption_store=consumption_store,
        approval_required=True,
        approval=approval,
        now=1700000020,
    )
    verified = verify_capability(cap_token, refund_500_action, "agent-support-01", ctx)
    assert verified.valid is True
    assert verified.approval_verified is True
    assert approval.consumed is True


def test_approval_for_500_rejected_for_5000(refund_500_action: dict) -> None:
    """Approval for ₹500 (50000 paise) must NEVER authorize ₹5,000 (500000 paise)."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)

    approval = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-alice", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000310,
    )

    refund_5000_action = copy.deepcopy(refund_500_action)
    refund_5000_action["arguments"]["amount_minor"] = 500000
    digest_5000 = calculate_action_digest(refund_5000_action)

    with pytest.raises(ApprovalVerificationError) as exc_info:
        verify_approval(
            approval,
            digest_5000,
            expected_action=refund_5000_action,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000020,
        )
    assert exc_info.value.error_code == "APPROVAL_ACTION_MISMATCH"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda a: a.__setitem__("resource", "orders/ORDER-999"),
        lambda a: a.__setitem__("tenant_id", "tenant-other"),
        lambda a: a.__setitem__("tool", "wire_transfer"),
        lambda a: a.__setitem__("environment", "production"),
    ],
)
def test_approval_rejected_when_order_tenant_tool_or_env_changes(
    refund_500_action: dict, mutator
) -> None:
    """Approval for one order, tenant, tool, or environment must not authorize another."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)

    approval = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-alice", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000310,
    )

    different_action = copy.deepcopy(refund_500_action)
    mutator(different_action)
    different_digest = calculate_action_digest(different_action)

    with pytest.raises(ApprovalVerificationError) as exc_info:
        verify_approval(
            approval,
            different_digest,
            expected_action=different_action,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000020,
        )
    assert exc_info.value.error_code == "APPROVAL_ACTION_MISMATCH"


def test_rejected_or_expired_approval_never_authorizes(refund_500_action: dict) -> None:
    """Rejected or expired approvals must be rejected."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    digest = calculate_action_digest(refund_500_action)

    rejected_appr = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-alice", "tenant-demo"),
        decision=ApprovalDecision.REJECTED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000310,
    )
    with pytest.raises(ApprovalVerificationError) as exc_info:
        verify_approval(
            rejected_appr,
            digest,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000020,
        )
    assert exc_info.value.error_code == "APPROVAL_REJECTED"

    expired_appr = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-alice", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000050,
    )
    with pytest.raises(ApprovalVerificationError) as exc_info2:
        verify_approval(
            expired_appr,
            digest,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000100,
        )
    assert exc_info2.value.error_code == "APPROVAL_EXPIRED"


def test_approval_replay_prevention_single_use_a4(refund_500_action: dict) -> None:
    """A4: Approval cannot be reused once consumed."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    digest = calculate_action_digest(refund_500_action)
    store = ApprovalConsumptionStore()

    approval = create_approval_record(
        action=refund_500_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-alice", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000310,
    )

    # First consumption succeeds
    res1 = verify_approval(
        approval.to_dict(),
        digest,
        key_manager=key_mgr.public_verifier_store(),
        now=1700000020,
        consume=True,
        consumption_store=store,
    )
    assert res1.valid is True

    # Second attempt with the same approval record fails
    with pytest.raises(ApprovalVerificationError) as exc_info:
        verify_approval(
            approval.to_dict(),
            digest,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000025,
            consume=True,
            consumption_store=store,
        )
    assert exc_info.value.error_code == "APPROVAL_ALREADY_CONSUMED"


def test_self_approval_by_agent_principal_rejected(refund_500_action: dict) -> None:
    """Agent cannot approve its own action."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)

    with pytest.raises(ApprovalVerificationError) as exc_info:
        create_approval_record(
            action=refund_500_action,
            tenant_id="tenant-demo",
            request_id="intent-demo-001",
            approver_context=AuthenticatedApproverContext("agent-support-01", "tenant-demo"),
            decision=ApprovalDecision.APPROVED,
            signing_key=appr_key,
        )
    assert exc_info.value.error_code == "SELF_APPROVAL_PROHIBITED"
