"""Component D — Signed Execution Receipts for AgentShield V2.

Records the cryptographically signed outcome of a protected execution so any third
party or audit verifier can verify the receipt independently using public keys.

Security & Trust Notes:
- Separate signing keys (`KeyPurpose.RECEIPT`) are used for receipts versus
  capabilities (`KeyPurpose.CAPABILITY`). This prevents a compromised gateway key
  from forging execution receipts, and prevents a compromised executor key from
  issuing capabilities.
- A receipt signature proves that the holder of the executor's receipt signing key
  attested to the execution outcome (`SUCCEEDED`, `FAILED_FINAL`, or `UNKNOWN`) for
  the exact `action_digest` and `execution_id`. It does not by itself prove external
  world state without correlating against the durable execution record and downstream
  idempotency log.
"""

from __future__ import annotations

import hmac
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Union

from .action_digest import calculate_action_digest, is_valid_sha256_hex
from .canonicalization import (
    CanonicalAction,
    CanonicalizationError,
    _validate_identifier,
    canonicalize_json_object,
    coerce_to_mapping,
    parse_strict_json,
)
from .key_management import (
    KeyManagementError,
    KeyManager,
    KeyPurpose,
    ManagedKey,
    b64url_decode,
    b64url_encode,
    create_default_key_manager,
)

RECEIPT_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-RECEIPT-V1\x00"
SUPPORTED_RECEIPT_SCHEMA_VERSIONS = {1}


class ExecutionResultStatus(str, Enum):
    """Distinguishes success, definitive failure, and uncertain execution outcomes."""

    SUCCEEDED = "SUCCEEDED"
    FAILED_FINAL = "FAILED_FINAL"
    UNKNOWN = "UNKNOWN"


from .exceptions import AgentShieldSecurityError


class ReceiptVerificationError(AgentShieldSecurityError):
    """Raised when an execution receipt fails creation, signing, or verification."""

    def __init__(self, message: str, error_code: str = "RECEIPT_VERIFICATION_FAILED") -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass
class ExecutionReceipt:
    """Structured execution receipt bound to an exact action digest and capability ID."""

    receipt_id: str
    execution_id: str
    tenant_id: str
    principal_id: str
    action_digest: str
    capability_id: str
    execution_result: ExecutionResultStatus
    timestamp: int
    executor_id: str
    approval_id: Optional[str] = None
    receipt_schema_version: int = 1
    kid: Optional[str] = None
    signature: Optional[str] = None

    def signable_dict(self) -> dict[str, Any]:
        """Return the canonical dictionary covered by the Ed25519 receipt signature."""
        if not self.kid:
            raise ReceiptVerificationError("Receipt is missing 'kid'.", error_code="MISSING_KEY_ID")
        return {
            "action_digest": self.action_digest,
            "approval_id": self.approval_id,
            "capability_id": self.capability_id,
            "execution_id": self.execution_id,
            "execution_result": (
                self.execution_result.value
                if isinstance(self.execution_result, ExecutionResultStatus)
                else str(self.execution_result)
            ),
            "executor_id": self.executor_id,
            "kid": self.kid,
            "principal_id": self.principal_id,
            "receipt_id": self.receipt_id,
            "receipt_schema_version": self.receipt_schema_version,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
        }

    def signable_bytes(self) -> bytes:
        """Return domain-separated canonical bytes for Ed25519 signing/verification."""
        return RECEIPT_DOMAIN_SEPARATOR + canonicalize_json_object(self.signable_dict())

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete signed receipt to a dictionary."""
        data = self.signable_dict() if self.kid else {
            "action_digest": self.action_digest,
            "approval_id": self.approval_id,
            "capability_id": self.capability_id,
            "execution_id": self.execution_id,
            "execution_result": (
                self.execution_result.value
                if isinstance(self.execution_result, ExecutionResultStatus)
                else str(self.execution_result)
            ),
            "executor_id": self.executor_id,
            "kid": self.kid,
            "principal_id": self.principal_id,
            "receipt_id": self.receipt_id,
            "receipt_schema_version": self.receipt_schema_version,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
        }
        data["signature"] = self.signature
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ExecutionReceipt":
        """Validate and construct an ExecutionReceipt from a mapping."""
        if not isinstance(data, Mapping):
            raise ReceiptVerificationError(
                "Receipt must be a mapping.",
                error_code="INVALID_RECEIPT_FORMAT",
            )
        try:
            raw_version = data.get("receipt_schema_version", 1)
            if isinstance(raw_version, bool) or not isinstance(raw_version, int):
                raise ValueError("receipt_schema_version must be an integer")
            if raw_version not in SUPPORTED_RECEIPT_SCHEMA_VERSIONS:
                raise ReceiptVerificationError(
                    f"Unsupported receipt_schema_version: {raw_version}",
                    error_code="UNSUPPORTED_RECEIPT_VERSION",
                )

            raw_result = data["execution_result"]
            if isinstance(raw_result, ExecutionResultStatus):
                exec_result = raw_result
            elif isinstance(raw_result, str):
                exec_result = ExecutionResultStatus(raw_result.upper())
            else:
                raise ValueError(f"Invalid execution_result: {raw_result!r}")

            ts = data["timestamp"]
            if isinstance(ts, bool) or not isinstance(ts, int):
                raise ValueError("timestamp must be an integer")

            digest = str(data["action_digest"])
            if not is_valid_sha256_hex(digest):
                raise ReceiptVerificationError(
                    f"Invalid SHA-256 action_digest in receipt: {digest!r}",
                    error_code="INVALID_ACTION_DIGEST",
                )

            approval_val = data.get("approval_id")
            norm_approval = (
                _validate_identifier(approval_val, "approval_id")
                if approval_val is not None
                else None
            )

            kid_val = data.get("kid")
            norm_kid = _validate_identifier(kid_val, "kid") if kid_val is not None else None

            return cls(
                receipt_id=_validate_identifier(
                    data.get("receipt_id") or f"rcpt-{uuid.uuid4().hex[:16]}",
                    "receipt_id",
                ),
                execution_id=_validate_identifier(data["execution_id"], "execution_id"),
                tenant_id=_validate_identifier(data["tenant_id"], "tenant_id"),
                principal_id=_validate_identifier(data["principal_id"], "principal_id"),
                action_digest=digest,
                capability_id=_validate_identifier(data["capability_id"], "capability_id"),
                approval_id=norm_approval,
                execution_result=exec_result,
                timestamp=ts,
                executor_id=_validate_identifier(
                    data.get("executor_id", "executor-01"),
                    "executor_id",
                ),
                receipt_schema_version=raw_version,
                kid=norm_kid,
                signature=data.get("signature"),
            )
        except ReceiptVerificationError:
            raise
        except (KeyError, ValueError, CanonicalizationError) as exc:
            raise ReceiptVerificationError(
                f"Malformed execution receipt: {exc}",
                error_code="INVALID_RECEIPT_SCHEMA",
            ) from exc


@dataclass(frozen=True)
class ReceiptVerificationResult:
    """Structured result returned by `verify_execution_receipt`."""

    valid: bool
    receipt: Optional[ExecutionReceipt] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.valid

    @property
    def receipt_id(self) -> Optional[str]:
        return self.receipt.receipt_id if self.receipt else None

    @property
    def execution_id(self) -> Optional[str]:
        return self.receipt.execution_id if self.receipt else None

    @property
    def action_digest(self) -> Optional[str]:
        return self.receipt.action_digest if self.receipt else None

    @property
    def execution_result(self) -> Optional[str]:
        return self.receipt.execution_result.value if self.receipt else None

    def __bool__(self) -> bool:
        return self.valid


def sign_execution_receipt(
    receipt: Any,
    signing_key: Optional[Union[ManagedKey, KeyManager]] = None,
) -> ExecutionReceipt:
    """Sign an execution receipt using a trusted Ed25519 receipt signing key."""
    if signing_key is None:
        signing_key = create_default_key_manager().get_signing_key(purpose=KeyPurpose.RECEIPT)
    elif isinstance(signing_key, KeyManager):
        signing_key = signing_key.get_signing_key(purpose=KeyPurpose.RECEIPT)
    elif not isinstance(signing_key, ManagedKey):
        raise ReceiptVerificationError(
            "signing_key must be a ManagedKey or KeyManager instance.",
            error_code="INVALID_SIGNING_KEY",
        )
    if signing_key.purpose not in {KeyPurpose.RECEIPT, KeyPurpose.ALL}:
        raise ReceiptVerificationError(
            f"Key {signing_key.kid!r} has purpose {signing_key.purpose.value!r}, cannot sign execution receipts.",
            error_code="KEY_PURPOSE_MISMATCH",
        )

    if isinstance(receipt, ExecutionReceipt):
        rcpt_obj = receipt
    else:
        try:
            data = dict(coerce_to_mapping(receipt))
        except CanonicalizationError as exc:
            raise ReceiptVerificationError(
                "receipt must be an ExecutionReceipt, Mapping, or Pydantic model.",
                error_code="INVALID_RECEIPT_FORMAT",
            ) from exc
        if "action" in data and "action_digest" not in data:
            data["action_digest"] = calculate_action_digest(data.pop("action"))
        if "timestamp" not in data:
            data["timestamp"] = int(time.time())
        rcpt_obj = ExecutionReceipt.from_mapping(data)

    rcpt_obj.kid = signing_key.kid
    try:
        sig_bytes = signing_key.sign(rcpt_obj.signable_bytes())
    except KeyManagementError as exc:
        raise ReceiptVerificationError(str(exc), error_code=exc.error_code) from exc

    rcpt_obj.signature = b64url_encode(sig_bytes)
    return rcpt_obj


def verify_execution_receipt(
    signed_receipt: Any,
    *,
    key_manager: Optional[KeyManager] = None,
    signing_key: Optional[ManagedKey] = None,
    expected_action: Optional[Any] = None,
    expected_action_digest: Optional[str] = None,
    expected_execution_id: Optional[str] = None,
    expected_tenant_id: Optional[str] = None,
    expected_principal_id: Optional[str] = None,
    expected_capability_id: Optional[str] = None,
    allow_retired_keys: bool = True,
    clock_skew_seconds: int = 5,
    raise_on_error: bool = True,
) -> ReceiptVerificationResult:
    """Independently verify a signed execution receipt without trusting the issuer service."""

    def _fail(code: str, msg: str) -> ReceiptVerificationResult:
        if raise_on_error:
            raise ReceiptVerificationError(msg, error_code=code)
        return ReceiptVerificationResult(valid=False, error_code=code, error_message=msg)

    # 1. Parse and validate receipt structure
    try:
        if isinstance(signed_receipt, ExecutionReceipt):
            # Re-validate via mapping to catch any post-signing attribute mutation
            rcpt = ExecutionReceipt.from_mapping(signed_receipt.to_dict())
        elif isinstance(signed_receipt, (str, bytes)):
            parsed = parse_strict_json(signed_receipt)
            rcpt = ExecutionReceipt.from_mapping(parsed)
        else:
            rcpt = ExecutionReceipt.from_mapping(coerce_to_mapping(signed_receipt))
    except (ReceiptVerificationError, CanonicalizationError) as exc:
        code = getattr(exc, "error_code", "INVALID_RECEIPT_SCHEMA")
        return _fail(code, str(exc))

    if not rcpt.kid or not rcpt.signature:
        return _fail("UNSIGNED_RECEIPT", "Execution receipt is missing 'kid' or 'signature'.")

    # 2. Resolve verification key
    effective_mgr: KeyManager
    if key_manager is not None:
        effective_mgr = key_manager
    elif signing_key is not None:
        effective_mgr = KeyManager([signing_key.public_only()])
    else:
        effective_mgr = create_default_key_manager().public_verifier_store()

    try:
        ver_key = effective_mgr.get_verification_key(
            rcpt.kid,
            purpose=KeyPurpose.RECEIPT,
            record_timestamp=rcpt.timestamp,
            allow_retired=allow_retired_keys,
            clock_skew_seconds=clock_skew_seconds,
        )
    except KeyManagementError as exc:
        return _fail(exc.error_code, str(exc))

    # 3. Verify Ed25519 signature over canonical receipt bytes
    try:
        sig_bytes = b64url_decode(rcpt.signature)
    except Exception as exc:
        return _fail("INVALID_SIGNATURE_ENCODING", f"Invalid base64url signature encoding: {exc}")

    if not ver_key.verify_signature(sig_bytes, rcpt.signable_bytes()):
        return _fail(
            "INVALID_RECEIPT_SIGNATURE",
            "Execution receipt Ed25519 signature verification failed (receipt was modified or forged).",
        )

    # 4. Verify binding to expected action / digest if provided
    target_digest = expected_action_digest
    if expected_action is not None:
        try:
            computed_digest = calculate_action_digest(expected_action)
        except CanonicalizationError as exc:
            return _fail(exc.error_code, f"Invalid expected_action: {exc}")
        if target_digest is not None and not hmac.compare_digest(target_digest, computed_digest):
            return _fail(
                "RECEIPT_ACTION_MISMATCH",
                "expected_action_digest does not match canonical digest of expected_action.",
            )
        target_digest = computed_digest

    if target_digest is not None:
        if not is_valid_sha256_hex(target_digest) or not hmac.compare_digest(
            rcpt.action_digest, target_digest
        ):
            return _fail(
                "RECEIPT_ACTION_MISMATCH",
                f"Receipt action_digest ({rcpt.action_digest[:16]}...) does not match "
                f"expected action digest ({str(target_digest)[:16]}...).",
            )

    if expected_execution_id is not None and rcpt.execution_id != expected_execution_id:
        return _fail(
            "RECEIPT_EXECUTION_ID_MISMATCH",
            f"Receipt execution_id {rcpt.execution_id!r} != expected {expected_execution_id!r}.",
        )
    if expected_tenant_id is not None and rcpt.tenant_id != expected_tenant_id:
        return _fail(
            "RECEIPT_TENANT_MISMATCH",
            f"Receipt tenant_id {rcpt.tenant_id!r} != expected {expected_tenant_id!r}.",
        )
    if expected_principal_id is not None and rcpt.principal_id != expected_principal_id:
        return _fail(
            "RECEIPT_PRINCIPAL_MISMATCH",
            f"Receipt principal_id {rcpt.principal_id!r} != expected {expected_principal_id!r}.",
        )
    if expected_capability_id is not None and rcpt.capability_id != expected_capability_id:
        return _fail(
            "RECEIPT_CAPABILITY_ID_MISMATCH",
            f"Receipt capability_id {rcpt.capability_id!r} != expected {expected_capability_id!r}.",
        )

    return ReceiptVerificationResult(valid=True, receipt=rcpt)
