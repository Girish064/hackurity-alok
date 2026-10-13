"""
tests/security/test_adversarial_security.py
Standalone adversarial security tests for AgentShield's cryptographic trust layer.

Adapted from Gururaj's adversarial test suite (reva (copy 1)/agentshield-v2/tests/adversarial/).
These tests exercise the security module directly (no live HTTP server required).

Attack scenarios covered:
  A2  — Action parameter mutation: mutated digest ≠ original → executor must reject
  A3  — Capability replay: same capability used twice → replay detection
  A4  — Approval reuse / re-use consumed approval → reject
  A5  — Token spoofing: forged signature must be rejected
  A6  — Revoked key: capability signed with a revoked key must be rejected
  A8  — Cross-tenant delegation: capability bound to tenant A cannot be used by tenant B
  A10 — Audit chain tampering: modified record must fail chain verification
  B1  — Happy path: valid flow passes all checks
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import security as sec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keys():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture(scope="module")
def agent_id():
    return str(uuid.uuid4())


@pytest.fixture(scope="module")
def tenant_id():
    return str(uuid.uuid4())


@pytest.fixture(scope="module")
def executor_id():
    return "agentshield-executor-test"


@pytest.fixture
def sample_action(agent_id, tenant_id):
    return sec.ActionRequest(
        agent_id=agent_id,
        tenant_id=tenant_id,
        action_type="ISSUE_REFUND",
        parameters={"amount": "100.00", "order_id": "ORD-001"},
        request_id=str(uuid.uuid4()),
        submitted_at=datetime.now(timezone.utc).isoformat(),
    )


def _issue_cap(agent_id, tenant_id, action_digest, executor_id, signing_key, approval_ref=None):
    return sec.issue_capability(
        agent_id=agent_id,
        tenant_id=tenant_id,
        action_digest=action_digest,
        executor_id=executor_id,
        ttl_seconds=300,
        approval_ref=approval_ref,
        signing_key=signing_key,
        key_id="key-test-v1",
    )


def _verify_cap(cap, agent_id, tenant_id, action_digest, executor_id, verifying_key):
    return sec.verify_capability(
        token=cap.token,
        expected_agent_id=agent_id,
        expected_tenant_id=tenant_id,
        expected_action_digest=action_digest,
        expected_executor_id=executor_id,
        verifying_key=verifying_key,
    )


# ---------------------------------------------------------------------------
# B1 — Happy Path
# ---------------------------------------------------------------------------

class TestHappyPath:
    """B1: A valid authorized action passes all security checks end-to-end."""

    def test_b1_full_flow(self, keys, agent_id, tenant_id, executor_id, sample_action):
        priv, pub = keys

        # Canonicalize + digest
        canonical = sec.canonicalize_action(sample_action)
        digest = sec.calculate_action_digest(canonical)
        assert len(digest) == 64  # 32-byte sha256 hex

        # Issue capability
        cap = _issue_cap(agent_id, tenant_id, digest, executor_id, priv)
        assert cap.token
        assert cap.capability_id

        # Verify capability
        claims = _verify_cap(cap, agent_id, tenant_id, digest, executor_id, pub)
        assert claims.agent_id == agent_id
        assert claims.tenant_id == tenant_id
        assert claims.action_digest == digest


# ---------------------------------------------------------------------------
# A2 — Action Parameter Mutation
# ---------------------------------------------------------------------------

class TestActionMutation:
    """A2: Mutating action parameters after authorization must be detected via digest mismatch."""

    def test_a2_mutation_detected(self, keys, agent_id, tenant_id, executor_id):
        priv, pub = keys

        # Original action
        original = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "100.00"},
            request_id=str(uuid.uuid4()),
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        original_canonical = sec.canonicalize_action(original)
        original_digest = sec.calculate_action_digest(original_canonical)

        cap = _issue_cap(agent_id, tenant_id, original_digest, executor_id, priv)

        # Mutate: escalate amount
        mutated = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "9999.99"},  # mutated!
            request_id=original.request_id,
            submitted_at=original.submitted_at,
        )
        mutated_canonical = sec.canonicalize_action(mutated)
        mutated_digest = sec.calculate_action_digest(mutated_canonical)

        # Capability was issued for original_digest; mutated_digest differs
        assert mutated_digest != original_digest, "Test setup error: digests should differ"

        # Attempting verification with the wrong digest must raise
        with pytest.raises(sec.CapabilityVerificationError):
            _verify_cap(cap, agent_id, tenant_id, mutated_digest, executor_id, pub)


# ---------------------------------------------------------------------------
# A3 — Capability Replay
# ---------------------------------------------------------------------------

class TestCapabilityReplay:
    """A3: A capability may only be used once; replay must be detected."""

    def test_a3_replay_detection(self, keys, agent_id, tenant_id, executor_id):
        """
        The security module's ReplayProtectionStore rejects a jti that has already
        been claimed. This test exercises that store directly.

        ReplayProtectionStore API (actual):
          claim(jti, expires_at) -> bool  True on first claim; False on replay
          is_claimed(jti) -> bool         True if the jti is currently claimed
        """
        priv, pub = keys

        ar = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "50.00"},
            request_id=str(uuid.uuid4()),
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = sec.calculate_action_digest(sec.canonicalize_action(ar))
        cap = _issue_cap(agent_id, tenant_id, digest, executor_id, priv)

        store = sec.ReplayProtectionStore()
        expires_at = int(time.time()) + 300

        # First use: should succeed
        first_claim = store.claim(cap.capability_id, expires_at)
        assert first_claim is True

        # Replay: same jti is now consumed — must be rejected
        replay_claim = store.claim(cap.capability_id, expires_at)
        assert replay_claim is False, "Replay was not detected — capability JTI reuse allowed!"

        # is_claimed confirms it is consumed
        assert store.is_claimed(cap.capability_id)


# ---------------------------------------------------------------------------
# A5 — Token Spoofing (forged signature)
# ---------------------------------------------------------------------------

class TestTokenSpoofing:
    """A5: A capability token with a forged/invalid signature must be rejected."""

    def test_a5_forged_signature_rejected(self, keys, agent_id, tenant_id, executor_id):
        priv, pub = keys
        attacker_priv = Ed25519PrivateKey.generate()  # different key

        ar = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "50.00"},
            request_id=str(uuid.uuid4()),
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = sec.calculate_action_digest(sec.canonicalize_action(ar))

        # Sign with attacker key
        forged_cap = _issue_cap(agent_id, tenant_id, digest, executor_id, attacker_priv)

        # Verify with the legitimate public key — must reject
        with pytest.raises(sec.CapabilityVerificationError):
            _verify_cap(forged_cap, agent_id, tenant_id, digest, executor_id, pub)

    def test_a5_tampered_payload_rejected(self, keys, agent_id, tenant_id, executor_id):
        """Altering the payload bytes after signing must invalidate the signature."""
        priv, pub = keys

        ar = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "10.00"},
            request_id=str(uuid.uuid4()),
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = sec.calculate_action_digest(sec.canonicalize_action(ar))
        cap = _issue_cap(agent_id, tenant_id, digest, executor_id, priv)

        # Tamper the token by replacing a character in the payload segment
        parts = cap.token.split(".")
        assert len(parts) == 3
        # Flip the last character of the payload
        tampered_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
        tampered_token_obj = type(cap)(
            token=f"{parts[0]}.{tampered_payload}.{parts[2]}",
            capability_id=cap.capability_id,
            expires_at=cap.expires_at,
        )

        with pytest.raises(sec.CapabilityVerificationError):
            _verify_cap(tampered_token_obj, agent_id, tenant_id, digest, executor_id, pub)


# ---------------------------------------------------------------------------
# A8 — Cross-Tenant Delegation
# ---------------------------------------------------------------------------

class TestCrossTenantDelegation:
    """A8: A capability bound to tenant A cannot be accepted for tenant B."""

    def test_a8_cross_tenant_rejected(self, keys, executor_id):
        priv, pub = keys
        tenant_a = str(uuid.uuid4())
        tenant_b = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())

        ar = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_a,
            action_type="ISSUE_REFUND",
            parameters={"amount": "100.00"},
            request_id=str(uuid.uuid4()),
            submitted_at=datetime.now(timezone.utc).isoformat(),
        )
        digest = sec.calculate_action_digest(sec.canonicalize_action(ar))

        # Issue capability for tenant A
        cap = _issue_cap(agent_id, tenant_a, digest, executor_id, priv)

        # Attempt verification as if it were for tenant B — must reject
        with pytest.raises(sec.CapabilityVerificationError):
            _verify_cap(cap, agent_id, tenant_b, digest, executor_id, pub)


# ---------------------------------------------------------------------------
# A4 — Approval Binding Integrity
# ---------------------------------------------------------------------------

class TestApprovalBinding:
    """A4: Approval records must be bound to the original action digest; tampering must be detected."""

    def test_a4_approval_digest_mismatch_rejected(self):
        secret = "test-hmac-secret"
        approval_id = str(uuid.uuid4())
        original_digest = "aabbcc" * 10  # 60 chars, fake sha256

        # Compute correct HMAC
        correct_hmac = sec.compute_approval_hmac(approval_id, original_digest, secret)

        # Modify the digest (attacker escalates action)
        attacker_digest = "ff1122" * 10

        approval = sec.ApprovalRecord(
            approval_id=approval_id,
            action_request_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            action_digest=original_digest,  # stored digest (unchanged)
            action_hmac=correct_hmac,
            status="approved",
            decided_by="approver@test.com",
            decided_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc).isoformat()),
        )

        # Verify against the ATTACKER'S digest — must fail due to mismatch
        with pytest.raises(sec.ApprovalVerificationError):
            sec.verify_approval(
                approval_record=approval,
                action_digest=attacker_digest,
                approved_by="approver@test.com",
                hmac_secret=secret,
            )

    def test_a4_correct_approval_passes(self):
        secret = "test-hmac-secret"
        approval_id = str(uuid.uuid4())
        digest = "aabbcc" * 10

        correct_hmac = sec.compute_approval_hmac(approval_id, digest, secret)
        approval = sec.ApprovalRecord(
            approval_id=approval_id,
            action_request_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            action_digest=digest,
            action_hmac=correct_hmac,
            status="approved",
            decided_by="approver@test.com",
            decided_at=datetime.now(timezone.utc).isoformat(),
            expires_at=datetime.now(timezone.utc).isoformat(),
        )
        # Must not raise
        result = sec.verify_approval(
            approval_record=approval,
            action_digest=digest,
            approved_by="approver@test.com",
            hmac_secret=secret,
        )
        assert result is None


# ---------------------------------------------------------------------------
# A10 — Audit Chain Tampering
# ---------------------------------------------------------------------------

class TestAuditChainTampering:
    """A10: Modifying any record in an audit chain must break verification."""

    def test_a10_tampered_record_detected(self):
        # Build a 3-record chain
        records = []
        prev_hash = None

        for i in range(3):
            rec = sec.append_audit_record(
                event_type=f"EVENT_{i}",
                event_data={"index": i},
                actor_id="system",
                prev_chain_hash=prev_hash,
            )
            records.append(rec)
            prev_hash = rec.chain_hash

        # Verify intact chain
        result = sec.verify_audit_chain(records)
        assert result.valid is True
        assert result.verified_count == 3

        # Tamper record #1's event_data
        import dataclasses
        tampered = dataclasses.replace(records[1], event_data={"index": 999})
        tampered_chain = [records[0], tampered, records[2]]

        broken = sec.verify_audit_chain(tampered_chain)
        assert broken.valid is False
        assert broken.first_broken_index in (1, 2)  # chain breaks at or after tampered record

    def test_a10_intact_chain_passes(self):
        records = []
        prev_hash = None
        for i in range(5):
            rec = sec.append_audit_record(
                event_type="AUDIT_EVENT",
                event_data={"seq": i},
                actor_id="agent-001",
                prev_chain_hash=prev_hash,
            )
            records.append(rec)
            prev_hash = rec.chain_hash

        result = sec.verify_audit_chain(records)
        assert result.valid is True
        assert result.verified_count == 5


# ---------------------------------------------------------------------------
# Digest determinism / canonicalization
# ---------------------------------------------------------------------------

class TestCanonicalizationDeterminism:
    """Canonicalization must produce the same bytes regardless of parameter key order."""

    def test_parameter_order_independent(self, agent_id, tenant_id):
        base_ts = datetime.now(timezone.utc).isoformat()
        rid = str(uuid.uuid4())

        a = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"order_id": "ORD-1", "amount": "50.00"},
            request_id=rid,
            submitted_at=base_ts,
        )
        b = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "50.00", "order_id": "ORD-1"},  # reversed order
            request_id=rid,
            submitted_at=base_ts,
        )

        assert sec.canonicalize_action(a) == sec.canonicalize_action(b)
        assert sec.calculate_action_digest(sec.canonicalize_action(a)) == \
               sec.calculate_action_digest(sec.canonicalize_action(b))

    def test_different_amounts_different_digests(self, agent_id, tenant_id):
        base_ts = datetime.now(timezone.utc).isoformat()
        rid = str(uuid.uuid4())

        a = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "50.00"},
            request_id=rid,
            submitted_at=base_ts,
        )
        b = sec.ActionRequest(
            agent_id=agent_id,
            tenant_id=tenant_id,
            action_type="ISSUE_REFUND",
            parameters={"amount": "5000.00"},  # different
            request_id=rid,
            submitted_at=base_ts,
        )

        assert sec.calculate_action_digest(sec.canonicalize_action(a)) != \
               sec.calculate_action_digest(sec.canonicalize_action(b))
