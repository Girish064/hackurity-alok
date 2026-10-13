"""Component C — Human Approval Binding and Verification for AgentShield V2.

Provides cryptographic and application-level binding between an authenticated human
approval decision and the exact canonical action digest requiring approval.

Security invariants:
- An approval is bound to the exact 64-character SHA-256 action_digest, tenant_id,
  request_id (or intent_id), authenticated approver_id, decision, and expiry.
- Changing the amount, resource, tenant, tool, or environment changes the action_digest
  and invalidates the approval.
- A REJECTED or expired approval never authorizes execution.
- Approvals are single-use; replaying a consumed approval is rejected.
- Approver identity must come from an authenticated context and must not be the
  requesting agent principal (separation of duties).
"""

from __future__ import annotations

import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Union

from .action_digest import calculate_action_digest, is_valid_sha256_hex
from .canonicalization import (
    CanonicalAction,
    CanonicalizationError,
    _validate_identifier,
    _validate_policy_version,
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

APPROVAL_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-APPROVAL-V1\x00"
DEFAULT_APPROVAL_TTL_SECONDS: int = 300


class ApprovalDecision(str, Enum):
    """Decision state of a human approval record."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

from .exceptions import AgentShieldSecurityError


class ApprovalVerificationError(AgentShieldSecurityError):
    """Raised when human approval verification fails."""

    def __init__(self, message: str, error_code: str = "APPROVAL_VERIFICATION_FAILED") -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class AuthenticatedApproverContext:
    """Represents an authenticated human approver identity established by the auth layer."""

    approver_id: str
    tenant_id: str
    auth_method: str = "session_jwt"
    authenticated_at: int = field(default_factory=lambda: int(time.time()))


class ApprovalConsumptionStore:
    """Thread-safe atomic consumption tracker for single-use human approvals.

    In production deployment, Alok can back this interface with Redis SET NX
    and PostgreSQL conditional UPDATE (... WHERE consumed = FALSE).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, int] = {}

    def try_consume(self, approval_id: str, consumed_at: Optional[int] = None) -> bool:
        """Atomically mark approval_id as consumed. Returns True only on first consumption."""
        if not approval_id or not isinstance(approval_id, str):
            return False
        ts = consumed_at if consumed_at is not None else int(time.time())
        with self._lock:
            if approval_id in self._consumed:
                return False
            self._consumed[approval_id] = ts
            return True

    def is_consumed(self, approval_id: str) -> bool:
        """Return True if approval_id has already been consumed."""
        with self._lock:
            return approval_id in self._consumed

    def reset(self) -> None:
        """Clear consumption state (for demo reset / isolated testing)."""
        with self._lock:
            self._consumed.clear()


@dataclass
class ApprovalRecord:
    """Action-bound human approval record with cryptographic signature support."""

    approval_id: str
    tenant_id: str
    request_id: str
    action_digest: str
    approver_id: str
    decision: ApprovalDecision
    created_at: int
    expires_at: int
    approval_policy_version: Union[int, str] = 1
    consumed: bool = False
    consumed_at: Optional[int] = None
    kid: Optional[str] = None
    signature: Optional[str] = None

    def signable_dict(self) -> dict[str, Any]:
        """Return the canonical dictionary of fields covered by the approval signature."""
        return {
            "action_digest": self.action_digest,
            "approval_id": self.approval_id,
            "approval_policy_version": self.approval_policy_version,
            "approver_id": self.approver_id,
            "created_at": self.created_at,
            "decision": self.decision.value if isinstance(self.decision, ApprovalDecision) else str(self.decision),
            "expires_at": self.expires_at,
            "kid": self.kid,
            "request_id": self.request_id,
            "schema_version": 1,
            "tenant_id": self.tenant_id,
        }

    def signable_bytes(self) -> bytes:
        """Return domain-separated canonical bytes for Ed25519 signing/verification."""
        return APPROVAL_DOMAIN_SEPARATOR + canonicalize_json_object(self.signable_dict())

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete approval record to a dictionary."""
        data = self.signable_dict()
        data["consumed"] = self.consumed
        data["consumed_at"] = self.consumed_at
        data["signature"] = self.signature
        return data

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ApprovalRecord":
        """Construct and validate an ApprovalRecord from a mapping."""
        if not isinstance(data, Mapping):
            raise ApprovalVerificationError(
                "Approval record must be a mapping.",
                error_code="INVALID_APPROVAL_FORMAT",
            )
        try:
            raw_decision = data["decision"]
            if isinstance(raw_decision, ApprovalDecision):
                decision = raw_decision
            elif isinstance(raw_decision, str):
                decision = ApprovalDecision(raw_decision.upper())
            else:
                raise ValueError(f"Invalid decision type: {type(raw_decision).__name__}")

            created_at = data["created_at"]
            expires_at = data["expires_at"]
            if isinstance(created_at, bool) or not isinstance(created_at, int):
                raise ValueError("created_at must be an integer timestamp")
            if isinstance(expires_at, bool) or not isinstance(expires_at, int):
                raise ValueError("expires_at must be an integer timestamp")

            return cls(
                approval_id=_validate_identifier(data["approval_id"], "approval_id"),
                tenant_id=_validate_identifier(data["tenant_id"], "tenant_id"),
                request_id=_validate_identifier(data["request_id"], "request_id"),
                action_digest=str(data["action_digest"]),
                approver_id=_validate_identifier(data["approver_id"], "approver_id"),
                decision=decision,
                created_at=created_at,
                expires_at=expires_at,
                approval_policy_version=_validate_policy_version(
                    data.get("approval_policy_version", 1)
                ),
                consumed=bool(data.get("consumed", False)),
                consumed_at=data.get("consumed_at"),
                kid=data.get("kid"),
                signature=data.get("signature"),
            )
        except (KeyError, ValueError, CanonicalizationError) as exc:
            raise ApprovalVerificationError(
                f"Malformed approval record: {exc}",
                error_code="INVALID_APPROVAL_SCHEMA",
            ) from exc


@dataclass(frozen=True)
class ApprovalVerificationResult:
    """Structured result of verifying a human approval record."""

    valid: bool
    approval_id: Optional[str] = None
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    action_digest: Optional[str] = None
    approver_id: Optional[str] = None
    decision: Optional[str] = None
    approval_policy_version: Optional[Union[int, str]] = None
    consumed: bool = False
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:
        return self.valid


def create_approval_record(
    *,
    action: Optional[Union[Mapping[str, Any], CanonicalAction, str, bytes]] = None,
    action_digest: Optional[str] = None,
    tenant_id: str,
    request_id: str,
    approver_context: Union[AuthenticatedApproverContext, str],
    decision: Union[ApprovalDecision, str],
    signing_key: Optional[ManagedKey] = None,
    approval_id: Optional[str] = None,
    created_at: Optional[int] = None,
    ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
    expires_at: Optional[int] = None,
    approval_policy_version: Union[int, str] = 1,
    principal_id: Optional[str] = None,
) -> ApprovalRecord:
    """Create and optionally sign an action-bound human approval record.

    Enforces:
    - Valid action_digest (computed from `action` if provided, or validated directly).
    - Authenticated approver context matching tenant_id.
    - Separation of duties: approver_id cannot equal the requesting agent principal_id.
    """
    norm_tenant = _validate_identifier(tenant_id, "tenant_id")
    norm_request = _validate_identifier(request_id, "request_id")

    if action is not None:
        computed_digest = calculate_action_digest(action)
        if action_digest is not None and not hmac.compare_digest(computed_digest, action_digest):
            raise ApprovalVerificationError(
                "Provided action_digest does not match canonical digest of provided action.",
                error_code="APPROVAL_ACTION_DIGEST_MISMATCH",
            )
        final_digest = computed_digest
        if isinstance(action, Mapping):
            action_tenant = action.get("tenant_id")
            if action_tenant and action_tenant != norm_tenant:
                raise ApprovalVerificationError(
                    f"Approval tenant_id {norm_tenant!r} does not match action tenant_id {action_tenant!r}.",
                    error_code="APPROVAL_TENANT_MISMATCH",
                )
            if principal_id is None:
                principal_id = action.get("principal_id")
        elif isinstance(action, CanonicalAction):
            if action.tenant_id != norm_tenant:
                raise ApprovalVerificationError(
                    f"Approval tenant_id {norm_tenant!r} does not match action tenant_id {action.tenant_id!r}.",
                    error_code="APPROVAL_TENANT_MISMATCH",
                )
            if principal_id is None:
                principal_id = action.principal_id
    elif action_digest is not None:
        if not is_valid_sha256_hex(action_digest):
            raise ApprovalVerificationError(
                f"Invalid SHA-256 hex digest: {action_digest!r}",
                error_code="INVALID_ACTION_DIGEST",
            )
        final_digest = action_digest
    else:
        raise ApprovalVerificationError(
            "Either 'action' or 'action_digest' must be provided to bind the approval.",
            error_code="MISSING_ACTION_BINDING",
        )

    if isinstance(approver_context, AuthenticatedApproverContext):
        if approver_context.tenant_id != norm_tenant:
            raise ApprovalVerificationError(
                f"Approver tenant {approver_context.tenant_id!r} cannot approve for tenant {norm_tenant!r}.",
                error_code="APPROVAL_TENANT_MISMATCH",
            )
        norm_approver = _validate_identifier(approver_context.approver_id, "approver_id")
    elif isinstance(approver_context, str):
        norm_approver = _validate_identifier(approver_context, "approver_id")
    else:
        raise ApprovalVerificationError(
            "Authenticated approver context is required.",
            error_code="UNAUTHENTICATED_APPROVER",
        )

    if principal_id is not None and norm_approver == principal_id:
        raise ApprovalVerificationError(
            f"Agent principal {principal_id!r} cannot self-approve its own action.",
            error_code="SELF_APPROVAL_PROHIBITED",
        )

    if isinstance(decision, ApprovalDecision):
        norm_decision = decision
    elif isinstance(decision, str):
        try:
            norm_decision = ApprovalDecision(decision.upper())
        except ValueError as exc:
            raise ApprovalVerificationError(
                f"Invalid approval decision {decision!r}; must be APPROVED or REJECTED.",
                error_code="INVALID_APPROVAL_DECISION",
            ) from exc
    else:
        raise ApprovalVerificationError(
            "Invalid approval decision type.",
            error_code="INVALID_APPROVAL_DECISION",
        )

    now_ts = created_at if created_at is not None else int(time.time())
    if ttl_seconds <= 0 and expires_at is None:
        raise ApprovalVerificationError(
            "Approval ttl_seconds must be positive.",
            error_code="INVALID_APPROVAL_EXPIRY",
        )
    exp_ts = expires_at if expires_at is not None else (now_ts + ttl_seconds)
    if exp_ts <= now_ts:
        raise ApprovalVerificationError(
            f"Approval expires_at ({exp_ts}) must be greater than created_at ({now_ts}).",
            error_code="INVALID_APPROVAL_EXPIRY",
        )

    record = ApprovalRecord(
        approval_id=_validate_identifier(
            approval_id if approval_id is not None else f"appr-{uuid.uuid4().hex[:16]}",
            "approval_id",
        ),
        tenant_id=norm_tenant,
        request_id=norm_request,
        action_digest=final_digest,
        approver_id=norm_approver,
        decision=norm_decision,
        created_at=now_ts,
        expires_at=exp_ts,
        approval_policy_version=_validate_policy_version(approval_policy_version),
        consumed=False,
        consumed_at=None,
    )

    if signing_key is not None:
        return sign_approval_record(record, signing_key)
    return record


def sign_approval_record(record: ApprovalRecord, signing_key: ManagedKey) -> ApprovalRecord:
    """Cryptographically sign an ApprovalRecord with an Ed25519 approval key."""
    if signing_key.purpose not in {KeyPurpose.APPROVAL, KeyPurpose.ALL}:
        raise ApprovalVerificationError(
            f"Key {signing_key.kid!r} (purpose={signing_key.purpose.value}) cannot sign approvals.",
            error_code="KEY_PURPOSE_MISMATCH",
        )
    try:
        record.kid = signing_key.kid
        sig_bytes = signing_key.sign(record.signable_bytes())
        record.signature = b64url_encode(sig_bytes)
        return record
    except KeyManagementError as exc:
        raise ApprovalVerificationError(str(exc), error_code=exc.error_code) from exc


def verify_approval(
    approval: Union[ApprovalRecord, Mapping[str, Any], str, bytes],
    expected_action_digest: Optional[str] = None,
    *,
    expected_action: Optional[Union[Mapping[str, Any], CanonicalAction, str, bytes]] = None,
    expected_tenant_id: Optional[str] = None,
    expected_request_id: Optional[str] = None,
    expected_approval_id: Optional[str] = None,
    expected_principal_id: Optional[str] = None,
    key_manager: Optional[KeyManager] = None,
    require_signature: bool = False,
    now: Optional[int] = None,
    clock_skew_seconds: int = 5,
    consume: bool = False,
    consumption_store: Optional[ApprovalConsumptionStore] = None,
    raise_on_error: bool = True,
) -> ApprovalVerificationResult:
    """Verify that a human approval record is authentic, unexpired, unconsumed, and bound to the exact action."""

    def _fail(code: str, msg: str) -> ApprovalVerificationResult:
        if raise_on_error:
            raise ApprovalVerificationError(msg, error_code=code)
        return ApprovalVerificationResult(valid=False, error_code=code, error_message=msg)

    # 1. Parse approval object
    try:
        if isinstance(approval, ApprovalRecord):
            record = approval
        elif isinstance(approval, (str, bytes)):
            parsed = parse_strict_json(approval)
            record = ApprovalRecord.from_mapping(parsed)
        else:
            record = ApprovalRecord.from_mapping(coerce_to_mapping(approval))
    except (ApprovalVerificationError, CanonicalizationError) as exc:
        code = getattr(exc, "error_code", "INVALID_APPROVAL_SCHEMA")
        return _fail(code, str(exc))

    # 2. Compute / validate expected action digest
    target_digest = expected_action_digest
    if expected_action is not None:
        try:
            action_digest_from_obj = calculate_action_digest(expected_action)
        except CanonicalizationError as exc:
            return _fail(exc.error_code, f"Invalid expected_action: {exc}")
        if target_digest is not None and not hmac.compare_digest(target_digest, action_digest_from_obj):
            return _fail(
                "APPROVAL_ACTION_MISMATCH",
                "expected_action_digest does not match digest of expected_action.",
            )
        target_digest = action_digest_from_obj

        if isinstance(expected_action, CanonicalAction):
            if expected_tenant_id is None:
                expected_tenant_id = expected_action.tenant_id
            if expected_principal_id is None:
                expected_principal_id = expected_action.principal_id
        elif not isinstance(expected_action, (str, bytes)):
            try:
                act_map = coerce_to_mapping(expected_action)
                if expected_tenant_id is None:
                    expected_tenant_id = act_map.get("tenant_id")
                if expected_principal_id is None:
                    expected_principal_id = act_map.get("principal_id")
            except CanonicalizationError:
                pass

    if not target_digest or not is_valid_sha256_hex(target_digest):
        return _fail("INVALID_EXPECTED_DIGEST", "A valid 64-char SHA-256 expected_action_digest is required.")

    if not is_valid_sha256_hex(record.action_digest):
        return _fail("INVALID_APPROVAL_DIGEST", "Approval record contains a malformed action_digest.")

    # 3. Verify cryptographic signature when key_manager is provided, signature is required, or signature is present
    if key_manager is not None or require_signature or record.signature is not None:
        if not record.kid or not record.signature:
            return _fail(
                "UNSIGNED_APPROVAL",
                "Approval record is missing cryptographic signature or key ID (kid).",
            )
        effective_key_mgr = (
            key_manager
            if key_manager is not None
            else create_default_key_manager().public_verifier_store()
        )
        try:
            ver_key = effective_key_mgr.get_verification_key(
                record.kid,
                purpose=KeyPurpose.APPROVAL,
                record_timestamp=record.created_at,
                allow_retired=False,
                clock_skew_seconds=clock_skew_seconds,
            )
            sig_bytes = b64url_decode(record.signature)
        except KeyManagementError as exc:
            return _fail(exc.error_code, str(exc))
        except Exception as exc:
            return _fail("INVALID_APPROVAL_SIGNATURE_ENCODING", f"Invalid signature encoding: {exc}")

        if not ver_key.verify_signature(sig_bytes, record.signable_bytes()):
            return _fail(
                "INVALID_APPROVAL_SIGNATURE",
                "Approval cryptographic signature verification failed.",
            )

    # 4. Check decision == APPROVED
    if record.decision != ApprovalDecision.APPROVED:
        return _fail(
            "APPROVAL_REJECTED",
            f"Approval {record.approval_id!r} has decision {record.decision.value!r}, not APPROVED.",
        )

    # 5. Check separation of duties (approver != agent principal)
    if expected_principal_id is not None and record.approver_id == expected_principal_id:
        return _fail(
            "SELF_APPROVAL_PROHIBITED",
            f"Approver {record.approver_id!r} cannot be the executing agent principal.",
        )

    # 6. Check exact action digest binding (constant-time)
    if not hmac.compare_digest(record.action_digest, target_digest):
        return _fail(
            "APPROVAL_ACTION_MISMATCH",
            f"Approval {record.approval_id!r} is bound to action digest {record.action_digest[:16]}..., "
            f"not requested action digest {target_digest[:16]}...",
        )

    # 7. Check tenant, request_id, and approval_id bindings
    if expected_approval_id is not None and record.approval_id != expected_approval_id:
        return _fail(
            "APPROVAL_ID_MISMATCH",
            f"Approval ID {record.approval_id!r} does not match expected {expected_approval_id!r}.",
        )

    if expected_tenant_id is not None and record.tenant_id != expected_tenant_id:
        return _fail(
            "APPROVAL_TENANT_MISMATCH",
            f"Approval tenant {record.tenant_id!r} does not match expected tenant {expected_tenant_id!r}.",
        )

    if expected_request_id is not None and record.request_id != expected_request_id:
        return _fail(
            "APPROVAL_REQUEST_MISMATCH",
            f"Approval request_id {record.request_id!r} does not match expected {expected_request_id!r}.",
        )

    # 8. Check creation and expiry timestamps
    current_time = now if now is not None else int(time.time())
    if record.expires_at <= record.created_at:
        return _fail("INVALID_APPROVAL_TIMESTAMPS", "Approval expires_at must be greater than created_at.")

    if record.created_at > current_time + clock_skew_seconds:
        return _fail(
            "APPROVAL_ISSUED_IN_FUTURE",
            f"Approval created_at ({record.created_at}) is in the future relative to now ({current_time}).",
        )

    if current_time > record.expires_at + clock_skew_seconds:
        return _fail(
            "APPROVAL_EXPIRED",
            f"Approval {record.approval_id!r} expired at {record.expires_at} (now={current_time}).",
        )

    # 9. Check single-use consumption state
    if record.consumed:
        return _fail(
            "APPROVAL_ALREADY_CONSUMED",
            f"Approval {record.approval_id!r} has already been consumed.",
        )

    if consumption_store is not None:
        if consume:
            if not consumption_store.try_consume(record.approval_id, consumed_at=current_time):
                return _fail(
                    "APPROVAL_ALREADY_CONSUMED",
                    f"Approval {record.approval_id!r} was already consumed in the consumption store.",
                )
        else:
            if consumption_store.is_consumed(record.approval_id):
                return _fail(
                    "APPROVAL_ALREADY_CONSUMED",
                    f"Approval {record.approval_id!r} is marked consumed in the consumption store.",
                )

    if consume and isinstance(approval, ApprovalRecord):
        approval.consumed = True
        approval.consumed_at = current_time

    return ApprovalVerificationResult(
        valid=True,
        approval_id=record.approval_id,
        tenant_id=record.tenant_id,
        request_id=record.request_id,
        action_digest=record.action_digest,
        approver_id=record.approver_id,
        decision=record.decision.value,
        approval_policy_version=record.approval_policy_version,
        consumed=record.consumed or consume,
    )
