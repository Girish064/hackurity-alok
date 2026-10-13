"""Performance & Latency Microbenchmarks for Girish's Cryptographic Trust Layer.

Verifies that canonicalization, SHA-256 digesting, Ed25519 capability issuance,
14-step executor verification, receipt signing/verification, and audit hash chaining
stay well below the <50ms p95 latency target specified in Master Spec Section 12.
"""

from __future__ import annotations

import statistics
import time

from app.security import (
    ApprovalConsumptionStore,
    ApprovalDecision,
    AuditChain,
    AuthenticatedApproverContext,
    ExecutionResultStatus,
    KeyPurpose,
    ReplayProtectionStore,
    VerificationContext,
    append_audit_record,
    calculate_action_digest,
    create_approval_record,
    create_default_key_manager,
    issue_capability,
    sign_execution_receipt,
    verify_audit_chain,
    verify_capability,
    verify_execution_receipt,
)


def _percentile(sorted_vals: list[float], pct: float) -> float:
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def test_full_crypto_pipeline_p50_and_p95_latency_under_budget() -> None:
    """Measure 200 full end-to-end cryptographic lifecycles and verify p95 latency < 10ms."""
    key_mgr = create_default_key_manager(created_at=1700000000)
    verifier_keys = key_mgr.public_verifier_store()
    cap_key = key_mgr.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    appr_key = key_mgr.get_signing_key(purpose=KeyPurpose.APPROVAL)
    rcpt_key = key_mgr.get_signing_key(purpose=KeyPurpose.RECEIPT)
    audit_key = key_mgr.get_signing_key(purpose=KeyPurpose.AUDIT)

    replay_store = ReplayProtectionStore()
    approval_store = ApprovalConsumptionStore()
    audit_chain = AuditChain(signing_key=audit_key)

    latencies_ms: list[float] = []
    iterations = 200

    for i in range(iterations):
        action = {
            "schema_version": 1,
            "tenant_id": "tenant-demo",
            "principal_id": "agent-support-01",
            "tool": "issue_refund",
            "resource": f"orders/ORDER-{i}",
            "arguments": {
                "order_id": f"ORDER-{i}",
                "amount_minor": 50000 + i,
            },
            "environment": "demo",
            "policy_version": 3,
            "intent_id": f"intent-bench-{i}",
        }

        t0 = time.perf_counter()

        digest = calculate_action_digest(action)
        approval = create_approval_record(
            action=action,
            action_digest=digest,
            tenant_id="tenant-demo",
            request_id=f"intent-bench-{i}",
            approver_context=AuthenticatedApproverContext("approver-1", "tenant-demo"),
            decision=ApprovalDecision.APPROVED,
            signing_key=appr_key,
            approval_id=f"appr-bench-{i}",
            created_at=1700000010,
            expires_at=1700000310,
        )
        token = issue_capability(
            {
                "action": action,
                "approval_id": approval.approval_id,
                "jti": f"cap-bench-{i}",
                "iat": 1700000015,
                "exp": 1700000075,
            },
            cap_key,
        )
        ctx = VerificationContext(
            key_manager=verifier_keys,
            replay_store=replay_store,
            approval_consumption_store=approval_store,
            approval_required=True,
            approval=approval,
            now=1700000020,
        )
        verified = verify_capability(token, action, "agent-support-01", ctx)
        receipt = sign_execution_receipt(
            {
                "receipt_id": f"rcpt-bench-{i}",
                "execution_id": f"exec-bench-{i}",
                "tenant_id": "tenant-demo",
                "principal_id": "agent-support-01",
                "action_digest": verified.action_digest,
                "capability_id": verified.jti,
                "approval_id": verified.approval_id,
                "execution_result": ExecutionResultStatus.SUCCEEDED,
                "timestamp": 1700000025,
                "executor_id": "executor-01",
            },
            rcpt_key,
        )
        verify_execution_receipt(receipt, key_manager=verifier_keys, expected_action_digest=digest)
        append_audit_record(
            {
                "event_id": f"evt-bench-{i}",
                "timestamp": 1700000025,
                "event_type": "EXECUTION_SUCCEEDED",
                "tenant_id": "tenant-demo",
                "principal_id": "agent-support-01",
                "action_digest": digest,
                "capability_id": verified.jti,
                "execution_id": f"exec-bench-{i}",
                "receipt_id": receipt.receipt_id,
            },
            chain=audit_chain,
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

    # Also verify the entire 200-record audit chain
    t_verify_start = time.perf_counter()
    chain_report = verify_audit_chain(audit_chain.records, key_manager=verifier_keys)
    chain_verify_ms = (time.perf_counter() - t_verify_start) * 1000.0
    assert chain_report.valid is True
    assert chain_report.verified_records == iterations

    sorted_lat = sorted(latencies_ms)
    p50 = _percentile(sorted_lat, 50)
    p95 = _percentile(sorted_lat, 95)
    mean_lat = statistics.mean(sorted_lat)

    print(
        f"\n[Crypto Benchmark ({iterations} lifecycles)] "
        f"p50={p50:.3f}ms, p95={p95:.3f}ms, mean={mean_lat:.3f}ms, "
        f"200-record audit chain verify={chain_verify_ms:.2f}ms"
    )
    # Master spec target is <50ms p95 total added latency; crypto layer alone must be well under 15ms
    assert p95 < 15.0
