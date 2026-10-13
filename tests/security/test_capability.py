"""Tests for Component B — Signed, Action-Bound Capabilities (`capability.py`)."""

from __future__ import annotations

import concurrent.futures
import copy

import pytest

from app.security.capability import (
    CapabilityVerificationError,
    ReplayProtectionStore,
    VerificationContext,
    issue_capability,
    verify_capability,
)
from app.security.key_management import (
    KeyPurpose,
    ManagedKey,
    b64url_encode,
    create_default_key_manager,
)


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


def test_valid_capability_issuance_and_verification(sample_action: dict) -> None:
    """B1: Valid benign refund action capability succeeds verification and claims JTI atomically."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    replay_store = ReplayProtectionStore()

    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=replay_store,
        now=1700000020,
    )
    verified = verify_capability(
        token,
        expected_action=sample_action,
        authenticated_principal="agent-support-01",
        verification_context=ctx,
    )
    assert verified.valid is True
    assert verified.claimed_atomically is True
    assert verified.tenant_id == "tenant-demo"
    assert verified.principal_id == "agent-support-01"
    assert verified.tool == "issue_refund"


def test_reject_forged_capability_signature(sample_action: dict) -> None:
    """Forged capability signature is rejected by the executor."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    header_b64, payload_b64, _ = token.split(".")
    forged_sig = b64url_encode(b"\x01" * 64)
    forged_token = f"{header_b64}.{payload_b64}.{forged_sig}"

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(forged_token, sample_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "INVALID_CAPABILITY_SIGNATURE"


def test_reject_unknown_signing_key(sample_action: dict) -> None:
    """Capability signed by an untrusted/unknown key ID is rejected."""
    rogue_key = ManagedKey.generate(kid="key-rogue-999", purpose=KeyPurpose.CAPABILITY, created_at=1700000000)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        rogue_key,
    )

    key_mgr = create_default_key_manager()
    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "UNKNOWN_SIGNING_KEY"


def test_reject_expired_capability(sample_action: dict) -> None:
    """Expired capability is rejected even when signature and action digest match."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000040},
        cap_key,
    )

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000100,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "CAPABILITY_EXPIRED"


def test_reject_action_substitution_amount_mutated_a2(sample_action: dict) -> None:
    """A2: Action substitution (authorized 50000 paise changed to 500000 paise) is rejected."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    substituted_action = copy.deepcopy(sample_action)
    substituted_action["arguments"]["amount_minor"] = 500000  # ₹5,000 instead of ₹500

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, substituted_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "ACTION_DIGEST_MISMATCH"


def test_reject_resource_or_tenant_substitution(sample_action: dict) -> None:
    """Capability used for a different resource or tenant is rejected."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )

    wrong_resource = copy.deepcopy(sample_action)
    wrong_resource["resource"] = "orders/ORDER-999"
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, wrong_resource, "agent-support-01", ctx)
    assert exc_info.value.error_code == "ACTION_DIGEST_MISMATCH"

    wrong_tenant = copy.deepcopy(sample_action)
    wrong_tenant["tenant_id"] = "tenant-other"
    with pytest.raises(CapabilityVerificationError) as exc_info2:
        verify_capability(token, wrong_tenant, "agent-support-01", ctx)
    assert exc_info2.value.error_code == "ACTION_DIGEST_MISMATCH"


def test_reject_identity_spoof_a5(sample_action: dict) -> None:
    """A5: Authenticated caller mismatch against authorized capability principal is rejected."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-attacker-99", ctx)
    assert exc_info.value.error_code == "PRINCIPAL_MISMATCH"


def test_reject_revoked_principal_after_authorization_a6(sample_action: dict) -> None:
    """A6: Agent revoked after capability issuance is denied at executor verification."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        revoked_principals={"agent-support-01"},
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "PRINCIPAL_REVOKED"


def test_concurrent_replay_protection_100_attempts_a3(sample_action: dict) -> None:
    """A3: 100 concurrent attempts reusing one capability result in exactly 1 claim and 99 rejections."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    shared_replay_store = ReplayProtectionStore()
    verifier_key_mgr = key_mgr.public_verifier_store()

    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    def _attempt(_: int) -> str:
        ctx = VerificationContext(
            key_manager=verifier_key_mgr,
            replay_store=shared_replay_store,
            now=1700000020,
        )
        try:
            verify_capability(token, sample_action, "agent-support-01", ctx)
            return "CLAIMED"
        except CapabilityVerificationError as exc:
            return exc.error_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        outcomes = list(pool.map(_attempt, range(100)))

    assert outcomes.count("CLAIMED") == 1
    assert outcomes.count("CAPABILITY_REPLAY_DETECTED") == 99


def test_fail_closed_on_missing_context_or_dependency_outage_a9(sample_action: dict) -> None:
    """A9: Missing verification context or unhealthy policy/replay/revocation dependency fails closed."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": sample_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, sample_action, "agent-support-01", None)
    assert exc_info.value.error_code == "MISSING_VERIFICATION_CONTEXT"

    outage_ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        replay_store_available=False,
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info2:
        verify_capability(token, sample_action, "agent-support-01", outage_ctx)
    assert exc_info2.value.error_code == "DEPENDENCY_OUTAGE_FAIL_CLOSED"
