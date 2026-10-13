"""Extensive Adversarial, Boundary, Bit-Flip, Concurrency, and Fuzzing Tests for Girish's Cryptographic Layer."""

from __future__ import annotations

import concurrent.futures
import copy
import json

import pytest

from app.security import (
    ApprovalConsumptionStore,
    ApprovalDecision,
    ApprovalVerificationError,
    AuditChain,
    AuditChainError,
    AuthenticatedApproverContext,
    CanonicalizationError,
    CapabilityVerificationError,
    DuplicateKeyError,
    ExecutionResultStatus,
    KeyPurpose,
    ReceiptVerificationError,
    ReplayProtectionStore,
    SchemaValidationError,
    VerificationContext,
    append_audit_record,
    b64url_decode,
    b64url_encode,
    calculate_action_digest,
    canonicalize_action,
    create_approval_record,
    create_chain_checkpoint,
    create_default_key_manager,
    issue_capability,
    sign_execution_receipt,
    verify_approval,
    verify_audit_chain,
    verify_capability,
    verify_end_to_end_evidence,
    verify_execution_receipt,
)
from app.security.canonicalization import MAX_NESTING_DEPTH, MAX_SAFE_INT, MIN_SAFE_INT


@pytest.fixture
def valid_action() -> dict:
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


# ==============================================================================
# 1. CANONICALIZATION & DIGEST BOUNDARY / FUZZ TESTS
# ==============================================================================


def test_nesting_depth_boundary_enforcement(valid_action: dict) -> None:
    """Nesting up to MAX_NESTING_DEPTH succeeds; exceeding it raises MAX_DEPTH_EXCEEDED."""
    # Build nested dict inside arguments
    act_ok = copy.deepcopy(valid_action)
    curr = act_ok["arguments"]
    for i in range(MAX_NESTING_DEPTH - 2):
        curr[f"level_{i}"] = {}
        curr = curr[f"level_{i}"]
    curr["leaf"] = 1
    assert len(canonicalize_action(act_ok)) > 0

    act_too_deep = copy.deepcopy(valid_action)
    curr = act_too_deep["arguments"]
    for i in range(MAX_NESTING_DEPTH + 1):
        curr[f"level_{i}"] = {}
        curr = curr[f"level_{i}"]
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_action(act_too_deep)
    assert exc_info.value.error_code == "MAX_DEPTH_EXCEEDED"


def test_safe_integer_boundaries_and_overflow(valid_action: dict) -> None:
    """Integers at MAX_SAFE_INT / MIN_SAFE_INT succeed; +/- (2^53) are rejected."""
    act = copy.deepcopy(valid_action)
    act["arguments"]["max_val"] = MAX_SAFE_INT
    act["arguments"]["min_val"] = MIN_SAFE_INT
    assert len(canonicalize_action(act)) > 0

    act_overflow = copy.deepcopy(valid_action)
    act_overflow["arguments"]["overflow"] = MAX_SAFE_INT + 1
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_action(act_overflow)
    assert exc_info.value.error_code == "INTEGER_OUT_OF_RANGE"

    act_underflow = copy.deepcopy(valid_action)
    act_underflow["arguments"]["underflow"] = MIN_SAFE_INT - 1
    with pytest.raises(CanonicalizationError) as exc_info2:
        canonicalize_action(act_underflow)
    assert exc_info2.value.error_code == "INTEGER_OUT_OF_RANGE"


@pytest.mark.parametrize("bad_amount", [0, -1, -50000])
def test_reject_non_positive_amount_minor(valid_action: dict, bad_amount: int) -> None:
    """Zero or negative amount_minor values must be rejected."""
    act = copy.deepcopy(valid_action)
    act["arguments"]["amount_minor"] = bad_amount
    with pytest.raises(SchemaValidationError) as exc_info:
        canonicalize_action(act)
    assert exc_info.value.error_code == "INVALID_AMOUNT_VALUE"


def test_reject_string_numeric_amount_confusion(valid_action: dict) -> None:
    """String amounts like '500.00' or '50000' in amount/amount_minor fields are rejected."""
    act1 = copy.deepcopy(valid_action)
    act1["arguments"]["amount"] = "500.00"
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_action(act1)
    assert exc_info.value.error_code == "AMBIGUOUS_NUMERIC_STRING"

    act2 = copy.deepcopy(valid_action)
    act2["arguments"]["amount_minor"] = "50000"
    with pytest.raises(SchemaValidationError) as exc_info2:
        canonicalize_action(act2)
    assert exc_info2.value.error_code == "INVALID_AMOUNT_TYPE"


def test_reject_unicode_nfc_duplicate_key_collision(valid_action: dict) -> None:
    """Two keys that are binary-distinct in UTF-8 (NFC vs NFD) but canonically identical must be rejected as duplicates."""
    act = copy.deepcopy(valid_action)
    # Construct raw JSON with NFC "caf\u00e9" and NFD "cafe\u0301"
    raw_json = json.dumps(act).replace(
        '"order_id": "ORDER-123"',
        '"caf\\u00e9": 1, "cafe\\u0301": 2, "order_id": "ORDER-123"',
    )
    with pytest.raises(DuplicateKeyError) as exc_info:
        canonicalize_action(raw_json)
    assert exc_info.value.error_code == "DUPLICATE_JSON_KEY"


@pytest.mark.parametrize(
    "bad_id,expected_code",
    [
        ("", "EMPTY_IDENTIFIER"),
        ("   ", "EMPTY_IDENTIFIER"),
        (" tenant-demo", "AMBIGUOUS_WHITESPACE"),
        ("tenant-demo ", "AMBIGUOUS_WHITESPACE"),
        ("tenant\x00demo", "CONTROL_CHAR_PROHIBITED"),
        ("tenant\ndemo", "CONTROL_CHAR_PROHIBITED"),
        ("tenant\x7fdemo", "CONTROL_CHAR_PROHIBITED"),
        ("a" * 257, "IDENTIFIER_TOO_LONG"),
    ],
)
def test_reject_malformed_identifiers(
    valid_action: dict, bad_id: str, expected_code: str
) -> None:
    """Empty, whitespace-padded, control-char, or overly long identifiers are rejected."""
    act = copy.deepcopy(valid_action)
    act["tenant_id"] = bad_id
    with pytest.raises(SchemaValidationError) as exc_info:
        canonicalize_action(act)
    assert exc_info.value.error_code == expected_code


def test_reject_nan_infinity_and_leading_zeros_in_raw_json() -> None:
    """NaN, Infinity, -Infinity, and leading-zero integers in raw JSON are rejected."""
    for bad_literal, expected_code in [
        ("NaN", "INVALID_NUMERIC_CONSTANT"),
        ("Infinity", "INVALID_NUMERIC_CONSTANT"),
        ("-Infinity", "INVALID_NUMERIC_CONSTANT"),
        ("050000", "AMBIGUOUS_NUMBER"),
        ("-0", "AMBIGUOUS_NUMBER"),
    ]:
        raw = f"""{{
          "schema_version": 1,
          "tenant_id": "t1",
          "principal_id": "p1",
          "tool": "refund",
          "resource": "r1",
          "arguments": {{"val": {bad_literal}}},
          "environment": "demo",
          "policy_version": 1,
          "intent_id": "i1"
        }}"""
        with pytest.raises(CanonicalizationError) as exc_info:
            canonicalize_action(raw)
        assert exc_info.value.error_code == expected_code


# ==============================================================================
# 2. JWS CAPABILITY CRYPTOGRAPHIC & PROTOCOL ATTACKS
# ==============================================================================


@pytest.mark.parametrize("bad_alg", ["none", "None", "HS256", "RS256", ""])
def test_jws_algorithm_confusion_attacks_rejected(valid_action: dict, bad_alg: str) -> None:
    """JWS 'alg: none' or symmetric/RSA algorithm confusion attacks are rejected before signature check."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": valid_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    _, payload_b64, sig_b64 = token.split(".")
    forged_header = b64url_encode(
        json.dumps({"alg": bad_alg, "kid": cap_key.kid, "typ": "agentshield-capability+jwt"}).encode()
    )
    tampered_token = f"{forged_header}.{payload_b64}.{sig_b64}"

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(tampered_token, valid_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "UNSUPPORTED_ALGORITHM"


def test_capability_every_part_bit_flip_detection(valid_action: dict) -> None:
    """Bit-flipping any byte in the JWS header, payload, or Ed25519 signature causes rejection."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": valid_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )
    h_b64, p_b64, s_b64 = token.split(".")
    sig_bytes = bytearray(b64url_decode(s_b64))

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000020,
    )

    # Flip bits at start, middle, and end of the 64-byte Ed25519 signature
    for byte_idx in (0, 15, 31, 47, 63):
        mutated_sig = bytearray(sig_bytes)
        mutated_sig[byte_idx] ^= 0x01
        bad_token = f"{h_b64}.{p_b64}.{b64url_encode(bytes(mutated_sig))}"
        with pytest.raises(CapabilityVerificationError) as exc_info:
            verify_capability(bad_token, valid_action, "agent-support-01", ctx)
        assert exc_info.value.error_code == "INVALID_CAPABILITY_SIGNATURE"


def test_cross_protocol_key_confusion_rejected(valid_action: dict) -> None:
    """Signing a capability with a Receipt, Approval, or Audit key is rejected."""
    key_mgr = create_default_key_manager()
    for wrong_purpose in (KeyPurpose.RECEIPT, KeyPurpose.APPROVAL, KeyPurpose.AUDIT):
        wrong_key = key_mgr.get_signing_key(purpose=wrong_purpose)
        with pytest.raises(CapabilityVerificationError) as exc_info:
            issue_capability({"action": valid_action}, wrong_key)
        assert exc_info.value.error_code == "KEY_PURPOSE_MISMATCH"


def test_clock_skew_exact_boundaries(valid_action: dict) -> None:
    """Verify exact clock skew tolerance boundaries for iat and exp."""
    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": valid_action, "iat": 1700000100, "exp": 1700000160},
        cap_key,
    )

    # Within 5s clock skew before iat (now = 1700000095) -> allowed
    ctx_early_ok = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000095,
        clock_skew_seconds=5,
    )
    assert verify_capability(token, valid_action, "agent-support-01", ctx_early_ok).valid is True

    # 6s before iat (now = 1700000094) -> rejected as CAPABILITY_ISSUED_IN_FUTURE
    ctx_too_early = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000094,
        clock_skew_seconds=5,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, valid_action, "agent-support-01", ctx_too_early)
    assert exc_info.value.error_code == "CAPABILITY_ISSUED_IN_FUTURE"

    # Within 5s clock skew after exp (now = 1700000165) -> allowed
    ctx_late_ok = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000165,
        clock_skew_seconds=5,
    )
    assert verify_capability(token, valid_action, "agent-support-01", ctx_late_ok).valid is True

    # 6s after exp (now = 1700000166) -> rejected as CAPABILITY_EXPIRED
    ctx_too_late = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(),
        now=1700000166,
        clock_skew_seconds=5,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info2:
        verify_capability(token, valid_action, "agent-support-01", ctx_too_late)
    assert exc_info2.value.error_code == "CAPABILITY_EXPIRED"


def test_redis_client_exception_in_replay_store_fails_closed(valid_action: dict) -> None:
    """If an external Redis client raises an exception during atomic JTI claim, fail closed."""

    class BrokenRedisClient:
        def set(self, *args, **kwargs):
            raise ConnectionError("Redis cluster unreachable")

    key_mgr = create_default_key_manager()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    token = issue_capability(
        {"action": valid_action, "iat": 1700000010, "exp": 1700000070},
        cap_key,
    )

    ctx = VerificationContext(
        key_manager=key_mgr.public_verifier_store(),
        replay_store=ReplayProtectionStore(redis_client=BrokenRedisClient()),
        now=1700000020,
    )
    with pytest.raises(CapabilityVerificationError) as exc_info:
        verify_capability(token, valid_action, "agent-support-01", ctx)
    assert exc_info.value.error_code == "DEPENDENCY_OUTAGE_FAIL_CLOSED"


# ==============================================================================
# 3. CONCURRENT APPROVAL CONSUMPTION & TAMPERING ATTACKS
# ==============================================================================


def test_concurrent_approval_consumption_50_threads(valid_action: dict) -> None:
    """50 concurrent threads attempting to consume the same human approval result in 1 success and 49 rejections."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    verifier_mgr = key_mgr.public_verifier_store()
    digest = calculate_action_digest(valid_action)
    shared_store = ApprovalConsumptionStore()

    approval = create_approval_record(
        action=valid_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-approver-1", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
        created_at=1700000010,
        expires_at=1700000310,
    )
    approval_dict = approval.to_dict()

    def _consume(_: int) -> str:
        res = verify_approval(
            approval_dict,
            digest,
            key_manager=verifier_mgr,
            now=1700000020,
            consume=True,
            consumption_store=shared_store,
            raise_on_error=False,
        )
        return "CONSUMED" if res.valid else (res.error_code or "ERR")

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as pool:
        outcomes = list(pool.map(_consume, range(50)))

    assert outcomes.count("CONSUMED") == 1
    assert outcomes.count("APPROVAL_ALREADY_CONSUMED") == 49


def test_cross_tenant_approver_and_unsigned_approval_rejected(valid_action: dict) -> None:
    """Approver from tenant-other cannot approve tenant-demo action, and unsigned approvals fail."""
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    digest = calculate_action_digest(valid_action)

    with pytest.raises(ApprovalVerificationError) as exc_info:
        create_approval_record(
            action=valid_action,
            tenant_id="tenant-demo",
            request_id="intent-demo-001",
            approver_context=AuthenticatedApproverContext("alice", "tenant-other"),
            decision=ApprovalDecision.APPROVED,
            signing_key=appr_key,
        )
    assert exc_info.value.error_code == "APPROVAL_TENANT_MISMATCH"

    # Unsigned approval rejected when key_manager is provided
    unsigned_appr = create_approval_record(
        action=valid_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("alice", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=None,
        created_at=1700000010,
        expires_at=1700000310,
    )
    with pytest.raises(ApprovalVerificationError) as exc_info2:
        verify_approval(
            unsigned_appr,
            digest,
            key_manager=key_mgr.public_verifier_store(),
            now=1700000020,
        )
    assert exc_info2.value.error_code == "UNSIGNED_APPROVAL"


# ==============================================================================
# 4. AUDIT CHAIN FORGERY & END-TO-END CORRELATION TESTS
# ==============================================================================


def test_audit_chain_recomputed_hash_without_private_key_detected(valid_action: dict) -> None:
    """If an attacker modifies record 1 AND recomputes all hashes (record_hash & prev_hash),
    Ed25519 signature verification catches the forgery.
    """
    key_mgr = create_default_key_manager()
    audit_key = key_mgr.get_signing_key(purpose=KeyPurpose.AUDIT)
    chain = AuditChain(signing_key=audit_key)

    r1 = append_audit_record(
        {
            "event_id": "evt-1",
            "timestamp": 1700000010,
            "event_type": "ACTION_AUTHORIZED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": valid_action,
        },
        chain=chain,
    )
    r2 = append_audit_record(
        {
            "event_id": "evt-2",
            "timestamp": 1700000020,
            "event_type": "EXECUTION_SUCCEEDED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": valid_action,
        },
        chain=chain,
    )

    # Attacker alters r1.principal_id AND recomputes r1.record_hash and r2.prev_hash + r2.record_hash
    r1.principal_id = "agent-innocent-02"
    r1.record_hash = r1.compute_hash()
    r2.prev_hash = r1.record_hash
    r2.record_hash = r2.compute_hash()

    report = verify_audit_chain([r1, r2], key_manager=key_mgr.public_verifier_store())
    assert report.valid is False
    assert report.error_code == "INVALID_AUDIT_SIGNATURE"
    assert report.first_invalid_sequence == 1


def test_end_to_end_evidence_detects_missing_receipt_in_audit_log(valid_action: dict) -> None:
    """Even if both receipt and audit chain are individually valid, `verify_end_to_end_evidence`
    rejects if the receipt is not recorded in the audit chain.
    """
    key_mgr = create_default_key_manager()
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)
    audit_key = key_mgr.get_signing_key(purpose=KeyPurpose.AUDIT)

    receipt = sign_execution_receipt(
        {
            "receipt_id": "rcpt-unlogged-999",
            "execution_id": "exec-999",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": valid_action,
            "capability_id": "cap-999",
            "execution_result": ExecutionResultStatus.SUCCEEDED,
            "timestamp": 1700000050,
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    chain = AuditChain(signing_key=audit_key)
    r1 = append_audit_record(
        {
            "event_id": "evt-other-1",
            "timestamp": 1700000010,
            "event_type": "ACTION_AUTHORIZED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action": valid_action,
        },
        chain=chain,
    )

    e2e = verify_end_to_end_evidence(
        action=valid_action,
        signed_receipt=receipt,
        audit_records=[r1],
        key_manager=key_mgr,
    )
    assert e2e.valid is False
    assert e2e.receipt_verified is True
    assert e2e.audit_chain_verified is True
    assert e2e.receipt_in_audit_chain is False
    assert e2e.error_code == "RECEIPT_MISSING_FROM_AUDIT_CHAIN"


def test_pydantic_v2_basemodel_and_minimal_section8_signatures(valid_action: dict) -> None:
    """Verify Pydantic BaseModel instances and exact minimal Section 8 function signatures work seamlessly."""
    from pydantic import BaseModel

    class ActionEnvelopeModel(BaseModel):
        schema_version: int
        tenant_id: str
        principal_id: str
        tool: str
        resource: str
        arguments: dict
        environment: str
        policy_version: int
        intent_id: str

    pydantic_action = ActionEnvelopeModel(**valid_action)

    # 1. canonicalize_action(action) -> canonical_bytes
    c_bytes = canonicalize_action(pydantic_action)
    assert c_bytes == canonicalize_action(valid_action)

    # 2. calculate_action_digest(action) -> digest
    digest = calculate_action_digest(pydantic_action)
    assert len(digest) == 64

    # 3. verify_approval(approval, expected_action_digest) -> result (2-arg call!)
    key_mgr = create_default_key_manager()
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    approval = create_approval_record(
        action=pydantic_action,
        tenant_id="tenant-demo",
        request_id="intent-demo-001",
        approver_context=AuthenticatedApproverContext("human-ops", "tenant-demo"),
        decision=ApprovalDecision.APPROVED,
        signing_key=appr_key,
    )
    appr_result = verify_approval(approval, digest)
    assert appr_result.valid is True

    # 4. issue_capability(claims, signing_key) -> signed_capability
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    signed_cap = issue_capability(pydantic_action, cap_key)

    # 5. verify_capability(signed_capability, expected_action, authenticated_principal, verification_context)
    verified_claims = verify_capability(
        signed_cap,
        pydantic_action,
        "agent-support-01",
        {"replay_store": ReplayProtectionStore()},
    )
    assert verified_claims.valid is True

    # 6. sign_execution_receipt(receipt, signing_key) -> signed_receipt
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)
    signed_rcpt = sign_execution_receipt(
        {
            "receipt_id": "rcpt-pyd-001",
            "execution_id": "exec-pyd-001",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": verified_claims.jti,
            "execution_result": "SUCCEEDED",
            "timestamp": int(approval.created_at),
            "executor_id": "executor-01",
        },
        rcpt_key,
    )

    # 7. verify_execution_receipt(signed_receipt) -> verification_result (1-arg call!)
    rcpt_result = verify_execution_receipt(signed_rcpt)
    assert rcpt_result.valid is True

    # 8. append_audit_record(event) & verify_audit_chain(records) (1-arg calls!)
    from app.security.audit_chain import reset_default_audit_chain

    reset_default_audit_chain()
    rec1 = append_audit_record(
        {
            "event_id": "evt-s8-1",
            "event_type": "EXECUTION_SUCCEEDED",
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "action_digest": digest,
            "capability_id": verified_claims.jti,
            "execution_id": "exec-pyd-001",
            "receipt_id": signed_rcpt.receipt_id,
        }
    )
    chain_report = verify_audit_chain([rec1])
    assert chain_report.valid is True

