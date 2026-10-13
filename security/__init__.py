"""
security/__init__.py
Public surface of the AgentShield security module.

Alok's backend imports ONLY from this module.
Girish replaces the internals of the subpackages without changing this file's exports.

NOTE: This is a REFERENCE STUB implementation using real cryptographic primitives
(Ed25519 via the `cryptography` library, SHA-256 for digests and chain hashes).
It is not a simulated or insecure mock. Girish should replace or extend the
subpackage implementations while keeping these exports stable.
"""
from security.canonicalization.canonicalizer import (
    canonicalize_action,
    calculate_action_digest,
)
from security.capabilities.issuer import issue_capability
from security.capabilities.verifier import verify_capability
from security.approvals.binder import verify_approval, compute_approval_hmac
from security.receipts.signer import sign_execution_receipt
from security.receipts.verifier import verify_execution_receipt
from security.audit.chain import append_audit_record, verify_audit_chain
from security.schemas import (
    ActionRequest,
    CapabilityToken,
    CapabilityClaims,
    ApprovalRecord,
    AuditRecord,
    AuditChainVerificationResult,
)
from security.exceptions import (
    AgentShieldSecurityError,
    CanonicalizationError,
    CapabilityVerificationError,
    CapabilityExpiredError,
    ApprovalVerificationError,
    ReceiptVerificationError,
    AuditChainError,
)

__all__ = [
    # Functions
    "canonicalize_action",
    "calculate_action_digest",
    "issue_capability",
    "verify_capability",
    "verify_approval",
    "compute_approval_hmac",
    "sign_execution_receipt",
    "verify_execution_receipt",
    "append_audit_record",
    "verify_audit_chain",
    # Schemas
    "ActionRequest",
    "CapabilityToken",
    "CapabilityClaims",
    "ApprovalRecord",
    "AuditRecord",
    "AuditChainVerificationResult",
    # Exceptions
    "AgentShieldSecurityError",
    "CanonicalizationError",
    "CapabilityVerificationError",
    "CapabilityExpiredError",
    "ApprovalVerificationError",
    "ReceiptVerificationError",
    "AuditChainError",
]
