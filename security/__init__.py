"""AgentShield V2 Cryptographic Trust Layer (`security`).

Exports all core cryptographic components from Girish's implementation along with
dual-interface adapter functions for full backward compatibility with the baseline application:
- Component A: Canonical action representation and domain-separated SHA-256 hashing.
- Component B: Ed25519-signed, action-bound JWS capabilities and executor verification.
- Component C: Cryptographic and application-level human approval binding.
- Component D: Signed execution receipts and independent receipt verification.
- Component E: Tamper-evident hash-chained audit records, checkpoints, and verifier.
"""
from __future__ import annotations

# Girish Primitives & Constants
from security.action_digest import (
    ACTION_DIGEST_DOMAIN_SEPARATOR,
    DIGEST_VERSION,
    STANDARD_TEST_VECTORS,
    calculate_action_digest_bytes,
    is_valid_sha256_hex,
    verify_action_digest,
)
from security.approval_binding import (
    APPROVAL_DOMAIN_SEPARATOR,
    ApprovalConsumptionStore,
    ApprovalDecision,
    ApprovalRecord as GirishApprovalRecord,
    ApprovalVerificationResult,
    AuthenticatedApproverContext,
    create_approval_record,
    sign_approval_record,
)
from security.audit_chain import (
    AUDIT_CHECKPOINT_DOMAIN_SEPARATOR,
    AUDIT_RECORD_DOMAIN_SEPARATOR,
    AUDIT_SIGNATURE_DOMAIN_SEPARATOR,
    GENESIS_PREV_HASH,
    AuditChain,
    AuditChainCheckpoint,
    AuditChainVerificationReport,
    AuditRecord as GirishAuditRecord,
    AuditVerificationIssue,
    create_chain_checkpoint,
    get_default_audit_records,
    reset_default_audit_chain,
)
from security.canonicalization import (
    REQUIRED_ACTION_FIELDS,
    SUPPORTED_SCHEMA_VERSIONS,
    CanonicalAction,
    canonicalize_json_object,
    parse_strict_json,
    validate_and_normalize_action,
)
from security.capability import (
    CAPABILITY_ALG,
    CAPABILITY_TOKEN_TYP,
    DEFAULT_CAPABILITY_AUDIENCE,
    DEFAULT_CAPABILITY_ISSUER,
    DEFAULT_CAPABILITY_TTL_SECONDS,
    MAX_CAPABILITY_TTL_SECONDS,
    CapabilityClaims,
    ReplayProtectionStore,
    VerificationContext,
    VerifiedCapabilityClaims,
    build_capability_claims_from_action,
)
from security.execution_receipt import (
    RECEIPT_DOMAIN_SEPARATOR,
    ExecutionReceipt,
    ExecutionResultStatus,
    ReceiptVerificationResult,
)
from security.key_management import (
    KeyManager,
    KeyPurpose,
    KeyStatus,
    ManagedKey,
    b64url_decode,
    b64url_encode,
    create_default_key_manager,
)
from security.verification import (
    EndToEndEvidenceReport,
    verify_end_to_end_evidence,
)
from security.oasb_evaluator import (
    OASBBenchmarkReport,
    OASBBenchmarkRunner,
    OASBCategoryScore,
    OASBSample,
    load_oasb_samples,
)

# Exceptions
from security.exceptions import (
    AgentShieldSecurityError,
    CanonicalizationError,
    DuplicateKeyError,
    SchemaValidationError,
    CapabilityVerificationError,
    CapabilityExpiredError,
    ApprovalVerificationError,
    ReceiptVerificationError,
    AuditChainError,
    KeyManagementError,
    UnknownKeyError,
    RevokedKeyError,
    RetiredKeyError,
)

# Schemas
from security.schemas import (
    ActionRequest,
    CapabilityToken,
    ApprovalRecord,
    AuditRecord,
    AuditChainVerificationResult,
)

# Backward-compatibility & dual-interface adapters
from security.adapters import (
    canonicalize_action,
    calculate_action_digest,
    issue_capability,
    verify_capability,
    sign_execution_receipt,
    verify_execution_receipt,
    compute_approval_hmac,
    verify_approval,
    append_audit_record,
    verify_audit_chain,
)

__all__ = [
    # Functions (Dual-Interface / Adapter)
    "canonicalize_action",
    "calculate_action_digest",
    "issue_capability",
    "verify_capability",
    "sign_execution_receipt",
    "verify_execution_receipt",
    "compute_approval_hmac",
    "verify_approval",
    "append_audit_record",
    "verify_audit_chain",
    # Component A
    "ACTION_DIGEST_DOMAIN_SEPARATOR",
    "DIGEST_VERSION",
    "REQUIRED_ACTION_FIELDS",
    "STANDARD_TEST_VECTORS",
    "SUPPORTED_SCHEMA_VERSIONS",
    "CanonicalAction",
    "calculate_action_digest_bytes",
    "canonicalize_json_object",
    "is_valid_sha256_hex",
    "parse_strict_json",
    "validate_and_normalize_action",
    "verify_action_digest",
    # Component B
    "CAPABILITY_ALG",
    "CAPABILITY_TOKEN_TYP",
    "DEFAULT_CAPABILITY_AUDIENCE",
    "DEFAULT_CAPABILITY_ISSUER",
    "DEFAULT_CAPABILITY_TTL_SECONDS",
    "MAX_CAPABILITY_TTL_SECONDS",
    "CapabilityClaims",
    "ReplayProtectionStore",
    "VerificationContext",
    "VerifiedCapabilityClaims",
    "build_capability_claims_from_action",
    # Component C
    "APPROVAL_DOMAIN_SEPARATOR",
    "ApprovalConsumptionStore",
    "ApprovalDecision",
    "ApprovalVerificationResult",
    "GirishApprovalRecord",
    "AuthenticatedApproverContext",
    "create_approval_record",
    "sign_approval_record",
    # Component D
    "RECEIPT_DOMAIN_SEPARATOR",
    "ExecutionReceipt",
    "ExecutionResultStatus",
    "ReceiptVerificationResult",
    # Component E
    "AUDIT_CHECKPOINT_DOMAIN_SEPARATOR",
    "AUDIT_RECORD_DOMAIN_SEPARATOR",
    "AUDIT_SIGNATURE_DOMAIN_SEPARATOR",
    "GENESIS_PREV_HASH",
    "AuditChain",
    "AuditChainCheckpoint",
    "AuditChainVerificationReport",
    "AuditVerificationIssue",
    "GirishAuditRecord",
    "create_chain_checkpoint",
    "get_default_audit_records",
    "reset_default_audit_chain",
    # Key Management & Evidence
    "EndToEndEvidenceReport",
    "KeyManager",
    "KeyPurpose",
    "KeyStatus",
    "ManagedKey",
    "b64url_decode",
    "b64url_encode",
    "create_default_key_manager",
    "verify_end_to_end_evidence",
    # OASB Benchmark
    "OASBBenchmarkReport",
    "OASBBenchmarkRunner",
    "OASBCategoryScore",
    "OASBSample",
    "load_oasb_samples",
    # Schemas
    "ActionRequest",
    "CapabilityToken",
    "ApprovalRecord",
    "AuditRecord",
    "AuditChainVerificationResult",
    # Exceptions
    "AgentShieldSecurityError",
    "CanonicalizationError",
    "DuplicateKeyError",
    "SchemaValidationError",
    "CapabilityVerificationError",
    "CapabilityExpiredError",
    "ApprovalVerificationError",
    "ReceiptVerificationError",
    "AuditChainError",
    "KeyManagementError",
    "UnknownKeyError",
    "RevokedKeyError",
    "RetiredKeyError",
]
