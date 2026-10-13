"""Unified Independent Verification Utility for AgentShield V2.

Exposes the complete cryptographic verification contract for the protected executor,
API layer (`POST /v1/audit/verify`), and red-team test suite, plus end-to-end
cross-artifact evidence verification.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Union

from .action_digest import (
    ACTION_DIGEST_DOMAIN_SEPARATOR,
    DIGEST_VERSION,
    STANDARD_TEST_VECTORS,
    calculate_action_digest,
    calculate_action_digest_bytes,
    is_valid_sha256_hex,
    verify_action_digest,
)
from .approval_binding import (
    ApprovalConsumptionStore,
    ApprovalDecision,
    ApprovalRecord,
    ApprovalVerificationError,
    ApprovalVerificationResult,
    AuthenticatedApproverContext,
    create_approval_record,
    sign_approval_record,
    verify_approval,
)
from .audit_chain import (
    GENESIS_PREV_HASH,
    AuditChain,
    AuditChainCheckpoint,
    AuditChainError,
    AuditChainVerificationReport,
    AuditRecord,
    AuditVerificationIssue,
    append_audit_record,
    create_chain_checkpoint,
    get_default_audit_records,
    reset_default_audit_chain,
    verify_audit_chain,
)
from .canonicalization import (
    CanonicalAction,
    CanonicalizationError,
    DuplicateKeyError,
    SchemaValidationError,
    canonicalize_action,
    canonicalize_json_object,
    parse_strict_json,
    validate_and_normalize_action,
)
from .capability import (
    CapabilityClaims,
    CapabilityVerificationError,
    ReplayProtectionStore,
    VerificationContext,
    VerifiedCapabilityClaims,
    build_capability_claims_from_action,
    issue_capability,
    verify_capability,
)
from .execution_receipt import (
    ExecutionReceipt,
    ExecutionResultStatus,
    ReceiptVerificationError,
    ReceiptVerificationResult,
    sign_execution_receipt,
    verify_execution_receipt,
)
from .key_management import (
    KeyManagementError,
    KeyManager,
    KeyPurpose,
    KeyStatus,
    ManagedKey,
    RetiredKeyError,
    RevokedKeyError,
    UnknownKeyError,
    create_default_key_manager,
)


@dataclass(frozen=True)
class EndToEndEvidenceReport:
    """Result of verifying an action, receipt, and audit trail as a correlated evidence bundle."""

    valid: bool
    action_digest: Optional[str] = None
    receipt_verified: bool = False
    audit_chain_verified: bool = False
    receipt_in_audit_chain: bool = False
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:
        return self.valid


def verify_end_to_end_evidence(
    *,
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes],
    signed_receipt: Union[ExecutionReceipt, Mapping[str, Any], str, bytes],
    audit_records: Sequence[Union[AuditRecord, Mapping[str, Any], str, bytes]],
    key_manager: Optional[KeyManager] = None,
    expected_checkpoint: Optional[Union[AuditChainCheckpoint, Mapping[str, Any]]] = None,
    allow_retired_keys: bool = True,
) -> EndToEndEvidenceReport:
    """Independently verify that a canonical action, signed execution receipt, and hash-chained
    audit log are all cryptographically valid and mutually consistent.
    """
    mgr = key_manager.public_verifier_store() if key_manager is not None else create_default_key_manager().public_verifier_store()

    try:
        canonical_act = validate_and_normalize_action(action)
        digest = calculate_action_digest(canonical_act)
    except CanonicalizationError as exc:
        return EndToEndEvidenceReport(
            valid=False,
            error_code=exc.error_code,
            error_message=f"Action canonicalization failed: {exc}",
        )

    rcpt_res = verify_execution_receipt(
        signed_receipt,
        key_manager=mgr,
        expected_action=canonical_act,
        expected_action_digest=digest,
        expected_tenant_id=canonical_act.tenant_id,
        expected_principal_id=canonical_act.principal_id,
        allow_retired_keys=allow_retired_keys,
        raise_on_error=False,
    )
    if not rcpt_res.valid or rcpt_res.receipt is None:
        return EndToEndEvidenceReport(
            valid=False,
            action_digest=digest,
            receipt_verified=False,
            error_code=rcpt_res.error_code,
            error_message=rcpt_res.error_message,
        )

    audit_report = verify_audit_chain(
        audit_records,
        key_manager=mgr,
        require_signatures=True,
        allow_retired_keys=allow_retired_keys,
        expected_checkpoint=expected_checkpoint,
        raise_on_error=False,
    )
    if not audit_report.valid:
        return EndToEndEvidenceReport(
            valid=False,
            action_digest=digest,
            receipt_verified=True,
            audit_chain_verified=False,
            error_code=audit_report.error_code,
            error_message=audit_report.error_message,
        )

    # Check that the verified receipt and action_digest appear in the verified audit log
    rcpt = rcpt_res.receipt
    matching_audit_found = False
    for raw_rec in audit_records:
        rec = raw_rec if isinstance(raw_rec, AuditRecord) else AuditRecord.from_mapping(
            parse_strict_json(raw_rec) if isinstance(raw_rec, (str, bytes)) else raw_rec
        )
        if (
            rec.receipt_id == rcpt.receipt_id
            and rec.execution_id == rcpt.execution_id
            and rec.action_digest is not None
            and hmac.compare_digest(rec.action_digest, digest)
            and rec.tenant_id == canonical_act.tenant_id
            and rec.principal_id == canonical_act.principal_id
        ):
            matching_audit_found = True
            break

    if not matching_audit_found:
        return EndToEndEvidenceReport(
            valid=False,
            action_digest=digest,
            receipt_verified=True,
            audit_chain_verified=True,
            receipt_in_audit_chain=False,
            error_code="RECEIPT_MISSING_FROM_AUDIT_CHAIN",
            error_message=(
                f"Receipt {rcpt.receipt_id!r} (execution_id={rcpt.execution_id!r}) was not found "
                "with matching action_digest in the verified audit chain."
            ),
        )

    return EndToEndEvidenceReport(
        valid=True,
        action_digest=digest,
        receipt_verified=True,
        audit_chain_verified=True,
        receipt_in_audit_chain=True,
    )
