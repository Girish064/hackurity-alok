"""Component E — Tamper-Evident Audit Chain and Independent Verifier for AgentShield V2.

Implements a domain-separated SHA-256 hash chain with Ed25519 per-record signatures
and optional signed chain-head checkpoints.

Construction:
    GENESIS_PREV_HASH = "0" * 64
    record_hash = SHA256(b"AGENTSHIELD-AUDIT-V1\\x00" + canonical_record_bytes)
    signature   = Ed25519.sign(b"AGENTSHIELD-AUDIT-SIG-V1\\x00" + record_hash.encode("ascii"))

Trust Assumptions & Limitations:
- Hash chaining + per-record signatures detect in-place record modification, insertion,
  deletion of intermediate records, sequence gaps, duplicates, and record reordering.
- A hash chain stored in a single mutable database cannot by itself prove that an attacker
  with database write access has not truncated the tail of the log or deleted the entire
  chain. To mitigate tail truncation and whole-chain replacement, use `AuditChainCheckpoint`
  (signed chain head stored in an independent store/WORM sink) and pass `expected_checkpoint`
  to `verify_audit_chain`.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union

from .action_digest import calculate_action_digest, is_valid_sha256_hex
from .canonicalization import (
    CanonicalizationError,
    _normalize_argument_value,
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

AUDIT_RECORD_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-AUDIT-V1\x00"
AUDIT_SIGNATURE_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-AUDIT-SIG-V1\x00"
AUDIT_CHECKPOINT_DOMAIN_SEPARATOR: bytes = b"AGENTSHIELD-AUDIT-CHECKPOINT-V1\x00"
GENESIS_PREV_HASH: str = "0" * 64


from .exceptions import AgentShieldSecurityError


class AuditChainError(AgentShieldSecurityError):
    """Raised when an audit record fails construction, signing, or verification."""

    def __init__(self, message: str, error_code: str = "AUDIT_CHAIN_ERROR") -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass
class AuditRecord:
    """Single tamper-evident record in the AgentShield V2 hash-chained audit log."""

    sequence_number: int
    event_id: str
    timestamp: int
    event_type: str
    tenant_id: str
    principal_id: str
    prev_hash: str
    record_hash: str
    action_digest: Optional[str] = None
    capability_id: Optional[str] = None
    approval_id: Optional[str] = None
    execution_id: Optional[str] = None
    receipt_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1
    kid: Optional[str] = None
    signature: Optional[str] = None

    def hashable_dict(self) -> dict[str, Any]:
        """Return the canonical dictionary of fields covered by `record_hash`."""
        return {
            "action_digest": self.action_digest,
            "approval_id": self.approval_id,
            "capability_id": self.capability_id,
            "details": self.details,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "execution_id": self.execution_id,
            "kid": self.kid,
            "prev_hash": self.prev_hash,
            "principal_id": self.principal_id,
            "receipt_id": self.receipt_id,
            "schema_version": self.schema_version,
            "sequence_number": self.sequence_number,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
        }

    def hashable_bytes(self) -> bytes:
        """Return deterministic canonical bytes used to compute `record_hash`."""
        return AUDIT_RECORD_DOMAIN_SEPARATOR + canonicalize_json_object(self.hashable_dict())

    def compute_hash(self) -> str:
        """Calculate the 64-char lowercase hex SHA-256 hash of this record."""
        return hashlib.sha256(self.hashable_bytes()).hexdigest()

    def signable_bytes(self) -> bytes:
        """Return domain-separated bytes signed by the Ed25519 audit key."""
        return AUDIT_SIGNATURE_DOMAIN_SEPARATOR + self.record_hash.encode("ascii")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete audit record to a dictionary."""
        data = self.hashable_dict()
        data["record_hash"] = self.record_hash
        data["signature"] = self.signature
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AuditRecord":
        """Construct an AuditRecord from a dictionary."""
        if not isinstance(data, Mapping):
            raise AuditChainError("Audit record must be a mapping.", error_code="INVALID_AUDIT_RECORD")
        try:
            seq = data["sequence_number"]
            ts = data["timestamp"]
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                raise ValueError("sequence_number must be a positive integer >= 1")
            if isinstance(ts, bool) or not isinstance(ts, int):
                raise ValueError("timestamp must be an integer")

            raw_details = data.get("details") or {}
            if not isinstance(raw_details, Mapping):
                raise ValueError("details must be a mapping")
            norm_details = _normalize_argument_value(raw_details, "details", depth=1)

            return cls(
                sequence_number=seq,
                event_id=_validate_identifier(data["event_id"], "event_id"),
                timestamp=ts,
                event_type=_validate_identifier(data["event_type"], "event_type"),
                tenant_id=_validate_identifier(data["tenant_id"], "tenant_id"),
                principal_id=_validate_identifier(data["principal_id"], "principal_id"),
                prev_hash=str(data["prev_hash"]),
                record_hash=str(data["record_hash"]),
                action_digest=(
                    str(data["action_digest"]) if data.get("action_digest") is not None else None
                ),
                capability_id=(
                    _validate_identifier(data["capability_id"], "capability_id")
                    if data.get("capability_id") is not None
                    else None
                ),
                approval_id=(
                    _validate_identifier(data["approval_id"], "approval_id")
                    if data.get("approval_id") is not None
                    else None
                ),
                execution_id=(
                    _validate_identifier(data["execution_id"], "execution_id")
                    if data.get("execution_id") is not None
                    else None
                ),
                receipt_id=(
                    _validate_identifier(data["receipt_id"], "receipt_id")
                    if data.get("receipt_id") is not None
                    else None
                ),
                details=norm_details,
                schema_version=int(data.get("schema_version", 1)),
                kid=(
                    _validate_identifier(data["kid"], "kid")
                    if data.get("kid") is not None
                    else None
                ),
                signature=data.get("signature"),
            )
        except (KeyError, ValueError, CanonicalizationError) as exc:
            raise AuditChainError(
                f"Malformed audit record: {exc}",
                error_code="INVALID_AUDIT_RECORD_SCHEMA",
            ) from exc


@dataclass(frozen=True)
class AuditChainCheckpoint:
    """Signed chain-head checkpoint used to detect tail truncation or full-chain rewrite."""

    checkpoint_id: str
    head_sequence_number: int
    head_record_hash: str
    timestamp: int
    kid: str
    signature: str

    def signable_bytes(self) -> bytes:
        payload = {
            "checkpoint_id": self.checkpoint_id,
            "head_record_hash": self.head_record_hash,
            "head_sequence_number": self.head_sequence_number,
            "kid": self.kid,
            "schema_version": 1,
            "timestamp": self.timestamp,
        }
        return AUDIT_CHECKPOINT_DOMAIN_SEPARATOR + canonicalize_json_object(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "head_record_hash": self.head_record_hash,
            "head_sequence_number": self.head_sequence_number,
            "kid": self.kid,
            "schema_version": 1,
            "signature": self.signature,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class AuditVerificationIssue:
    """Describes a specific integrity or signature failure detected in the audit chain."""

    index: int
    sequence_number: Optional[int]
    event_id: Optional[str]
    error_code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "sequence_number": self.sequence_number,
            "event_id": self.event_id,
            "error_code": self.error_code,
            "message": self.message,
        }


@dataclass(frozen=True)
class AuditChainVerificationReport:
    """Structured report returned by `verify_audit_chain`."""

    valid: bool
    total_records: int
    verified_records: int
    head_sequence_number: Optional[int] = None
    head_record_hash: Optional[str] = None
    first_invalid_sequence: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    issues: tuple[AuditVerificationIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:
        return self.valid

    def raise_for_invalid(self) -> None:
        """Raise AuditChainError if the audit chain verification report is not valid."""
        if not self.valid:
            raise AuditChainError(
                self.error_message or "Audit chain verification failed.",
                error_code=self.error_code or "AUDIT_CHAIN_TAMPERED",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_records": self.total_records,
            "verified_records": self.verified_records,
            "head_sequence_number": self.head_sequence_number,
            "head_record_hash": self.head_record_hash,
            "first_invalid_sequence": self.first_invalid_sequence,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class AuditChain:
    """Thread-safe append-only audit chain manager."""

    def __init__(self, signing_key: Optional[ManagedKey] = None) -> None:
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        if signing_key is None:
            default_mgr = create_default_key_manager()
            self._signing_key: Optional[ManagedKey] = default_mgr.get_signing_key(
                purpose=KeyPurpose.AUDIT
            )
        else:
            self._signing_key = signing_key

    @property
    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def reset(self, signing_key: Optional[ManagedKey] = None) -> None:
        with self._lock:
            self._records.clear()
            if signing_key is not None:
                self._signing_key = signing_key

    def append(
        self,
        event: Mapping[str, Any],
        *,
        signing_key: Optional[ManagedKey] = None,
    ) -> AuditRecord:
        """Append an event to this AuditChain instance atomically."""
        with self._lock:
            prev = self._records[-1] if self._records else None
            key = signing_key if signing_key is not None else self._signing_key
            rec = _build_audit_record(event, previous_record=prev, signing_key=key)
            self._records.append(rec)
            return rec


_DEFAULT_AUDIT_CHAIN = AuditChain()


def reset_default_audit_chain(signing_key: Optional[ManagedKey] = None) -> None:
    """Reset the module-level default audit chain (for demo reset and isolated unit tests)."""
    _DEFAULT_AUDIT_CHAIN.reset(signing_key=signing_key)


def get_default_audit_records() -> list[AuditRecord]:
    """Return a copy of records in the module-level default audit chain."""
    return _DEFAULT_AUDIT_CHAIN.records


def _build_audit_record(
    event: Any,
    *,
    previous_record: Optional[Union[AuditRecord, Mapping[str, Any]]] = None,
    signing_key: Optional[ManagedKey] = None,
) -> AuditRecord:
    try:
        event = coerce_to_mapping(event)
    except CanonicalizationError as exc:
        raise AuditChainError("Audit event must be a mapping or Pydantic model.", error_code="INVALID_EVENT_FORMAT") from exc

    if previous_record is not None:
        if isinstance(previous_record, AuditRecord):
            prev_rec = previous_record
        elif isinstance(previous_record, Mapping):
            prev_rec = AuditRecord.from_mapping(previous_record)
        else:
            raise AuditChainError("previous_record must be an AuditRecord or Mapping.")
        seq = prev_rec.sequence_number + 1
        prev_hash = prev_rec.record_hash
    else:
        seq = int(event.get("sequence_number", 1))
        prev_hash = str(event.get("prev_hash", GENESIS_PREV_HASH))

    if seq < 1:
        raise AuditChainError("sequence_number must be >= 1.", error_code="INVALID_SEQUENCE_NUMBER")
    if seq == 1 and prev_hash != GENESIS_PREV_HASH:
        raise AuditChainError(
            "Genesis audit record (sequence_number=1) must have prev_hash = '0'*64.",
            error_code="INVALID_GENESIS_PREV_HASH",
        )
    if not is_valid_sha256_hex(prev_hash):
        raise AuditChainError(
            f"Invalid prev_hash {prev_hash!r}; expected 64 lowercase hex chars.",
            error_code="INVALID_PREV_HASH",
        )

    action_digest = event.get("action_digest")
    if action_digest is None and "action" in event and event["action"] is not None:
        action_digest = calculate_action_digest(event["action"])
    if action_digest is not None and not is_valid_sha256_hex(action_digest):
        raise AuditChainError(
            f"Invalid action_digest {action_digest!r}; expected 64 lowercase hex chars.",
            error_code="INVALID_ACTION_DIGEST",
        )

    raw_details = event.get("details") or {}
    if not isinstance(raw_details, Mapping):
        raise AuditChainError("Audit event 'details' must be a mapping.", error_code="INVALID_DETAILS")
    norm_details = _normalize_argument_value(raw_details, "details", depth=1)

    ts = event.get("timestamp")
    now_ts = int(time.time()) if ts is None else ts
    if isinstance(now_ts, bool) or not isinstance(now_ts, int):
        raise AuditChainError("timestamp must be an integer.", error_code="INVALID_TIMESTAMP")

    if signing_key is not None and signing_key.purpose not in {KeyPurpose.AUDIT, KeyPurpose.ALL}:
        raise AuditChainError(
            f"Key {signing_key.kid!r} has purpose {signing_key.purpose.value!r}, cannot sign audit records.",
            error_code="KEY_PURPOSE_MISMATCH",
        )

    kid_val = signing_key.kid if signing_key is not None else event.get("kid")

    record = AuditRecord(
        sequence_number=seq,
        event_id=_validate_identifier(
            event.get("event_id") or f"evt-{uuid.uuid4().hex[:16]}",
            "event_id",
        ),
        timestamp=now_ts,
        event_type=_validate_identifier(event["event_type"], "event_type"),
        tenant_id=_validate_identifier(event["tenant_id"], "tenant_id"),
        principal_id=_validate_identifier(event["principal_id"], "principal_id"),
        prev_hash=prev_hash,
        record_hash="",
        action_digest=action_digest,
        capability_id=(
            _validate_identifier(event["capability_id"], "capability_id")
            if event.get("capability_id") is not None
            else None
        ),
        approval_id=(
            _validate_identifier(event["approval_id"], "approval_id")
            if event.get("approval_id") is not None
            else None
        ),
        execution_id=(
            _validate_identifier(event["execution_id"], "execution_id")
            if event.get("execution_id") is not None
            else None
        ),
        receipt_id=(
            _validate_identifier(event["receipt_id"], "receipt_id")
            if event.get("receipt_id") is not None
            else None
        ),
        details=norm_details,
        schema_version=int(event.get("schema_version", 1)),
        kid=_validate_identifier(kid_val, "kid") if kid_val is not None else None,
        signature=None,
    )

    record.record_hash = record.compute_hash()

    if signing_key is not None:
        try:
            sig_bytes = signing_key.sign(record.signable_bytes())
            record.signature = b64url_encode(sig_bytes)
        except KeyManagementError as exc:
            raise AuditChainError(str(exc), error_code=exc.error_code) from exc

    return record


def append_audit_record(
    event: Mapping[str, Any],
    *,
    previous_record: Optional[Union[AuditRecord, Mapping[str, Any]]] = None,
    signing_key: Optional[ManagedKey] = None,
    chain: Optional[AuditChain] = None,
) -> AuditRecord:
    """Append an event to the audit chain and return the signed, hash-linked AuditRecord.

    If `chain` is provided, appends to `chain`.
    If `previous_record` is explicitly provided (or `sequence_number` is in `event`), builds
    a standalone linked record.
    Otherwise, appends to the module-level default `AuditChain`.
    """
    if chain is not None:
        return chain.append(event, signing_key=signing_key)

    if previous_record is not None or "sequence_number" in event or "prev_hash" in event:
        key = signing_key
        if key is None:
            key = create_default_key_manager().get_signing_key(purpose=KeyPurpose.AUDIT)
        return _build_audit_record(event, previous_record=previous_record, signing_key=key)

    return _DEFAULT_AUDIT_CHAIN.append(event, signing_key=signing_key)


def create_chain_checkpoint(
    records: Sequence[Union[AuditRecord, Mapping[str, Any]]],
    signing_key: Optional[ManagedKey] = None,
    *,
    checkpoint_id: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> AuditChainCheckpoint:
    """Create a cryptographically signed checkpoint of the current audit chain head."""
    if not records:
        raise AuditChainError("Cannot create a checkpoint for an empty audit chain.", error_code="EMPTY_AUDIT_CHAIN")

    key = signing_key or create_default_key_manager().get_signing_key(purpose=KeyPurpose.AUDIT)
    if key.purpose not in {KeyPurpose.AUDIT, KeyPurpose.ALL}:
        raise AuditChainError(
            f"Key {key.kid!r} cannot sign audit checkpoints.",
            error_code="KEY_PURPOSE_MISMATCH",
        )

    last = records[-1]
    head_rec = last if isinstance(last, AuditRecord) else AuditRecord.from_mapping(last)
    cp_id = _validate_identifier(checkpoint_id or f"chk-{uuid.uuid4().hex[:16]}", "checkpoint_id")
    ts = timestamp if timestamp is not None else int(time.time())

    temp = AuditChainCheckpoint(
        checkpoint_id=cp_id,
        head_sequence_number=head_rec.sequence_number,
        head_record_hash=head_rec.record_hash,
        timestamp=ts,
        kid=key.kid,
        signature="",
    )
    sig_bytes = key.sign(temp.signable_bytes())
    return AuditChainCheckpoint(
        checkpoint_id=cp_id,
        head_sequence_number=head_rec.sequence_number,
        head_record_hash=head_rec.record_hash,
        timestamp=ts,
        kid=key.kid,
        signature=b64url_encode(sig_bytes),
    )


def verify_audit_chain(
    records: Sequence[Union[AuditRecord, Mapping[str, Any], str, bytes]],
    *,
    key_manager: Optional[KeyManager] = None,
    require_signatures: bool = True,
    allow_retired_keys: bool = True,
    expected_checkpoint: Optional[Union[AuditChainCheckpoint, Mapping[str, Any]]] = None,
    clock_skew_seconds: int = 5,
    raise_on_error: bool = False,
) -> AuditChainVerificationReport:
    """Independently verify hash links, sequence continuity, record integrity, signatures,
    and optional chain-head checkpoint for a sequence of audit records.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        report = AuditChainVerificationReport(
            valid=False,
            total_records=0,
            verified_records=0,
            error_code="INVALID_RECORDS_COLLECTION",
            error_message="records must be a sequence of AuditRecord or Mapping objects.",
        )
        if raise_on_error:
            report.raise_for_invalid()
        return report

    total = len(records)
    if total == 0:
        if expected_checkpoint is not None:
            report = AuditChainVerificationReport(
                valid=False,
                total_records=0,
                verified_records=0,
                error_code="AUDIT_CHAIN_TRUNCATED",
                error_message="Audit chain is empty, but a non-empty checkpoint was expected (whole-chain deletion detected).",
            )
            if raise_on_error:
                report.raise_for_invalid()
            return report
        return AuditChainVerificationReport(
            valid=True,
            total_records=0,
            verified_records=0,
        )

    mgr = key_manager if key_manager is not None else create_default_key_manager()
    issues: list[AuditVerificationIssue] = []
    seen_event_ids: set[str] = set()
    expected_prev_hash = GENESIS_PREV_HASH
    verified_count = 0
    last_valid_seq: Optional[int] = None
    last_valid_hash: Optional[str] = None

    for idx, raw_item in enumerate(records):
        expected_seq = idx + 1
        try:
            if isinstance(raw_item, AuditRecord):
                rec = AuditRecord.from_mapping(raw_item.to_dict())
            elif isinstance(raw_item, (str, bytes)):
                rec = AuditRecord.from_mapping(parse_strict_json(raw_item))
            elif isinstance(raw_item, Mapping):
                rec = AuditRecord.from_mapping(raw_item)
            else:
                issues.append(
                    AuditVerificationIssue(
                        index=idx,
                        sequence_number=None,
                        event_id=None,
                        error_code="INVALID_AUDIT_RECORD_FORMAT",
                        message=f"Record at index {idx} has invalid type {type(raw_item).__name__}.",
                    )
                )
                break
        except (AuditChainError, CanonicalizationError) as exc:
            issues.append(
                AuditVerificationIssue(
                    index=idx,
                    sequence_number=None,
                    event_id=None,
                    error_code=getattr(exc, "error_code", "INVALID_AUDIT_RECORD_SCHEMA"),
                    message=f"Record at index {idx} failed schema validation: {exc}",
                )
            )
            break

        # 1. Check sequence continuity (detects deletions, gaps, duplicates, or reordering)
        if rec.sequence_number != expected_seq:
            issues.append(
                AuditVerificationIssue(
                    index=idx,
                    sequence_number=rec.sequence_number,
                    event_id=rec.event_id,
                    error_code="SEQUENCE_DISCONTINUITY",
                    message=(
                        f"Audit sequence discontinuity at index {idx}: "
                        f"expected sequence_number={expected_seq}, got {rec.sequence_number}."
                    ),
                )
            )

        # 2. Check duplicate event_id
        if rec.event_id in seen_event_ids:
            issues.append(
                AuditVerificationIssue(
                    index=idx,
                    sequence_number=rec.sequence_number,
                    event_id=rec.event_id,
                    error_code="DUPLICATE_EVENT_ID",
                    message=f"Duplicate audit event_id {rec.event_id!r} at index {idx}.",
                )
            )
        seen_event_ids.add(rec.event_id)

        # 3. Check previous-record hash link
        if not is_valid_sha256_hex(rec.prev_hash) or not hmac.compare_digest(
            rec.prev_hash, expected_prev_hash
        ):
            issues.append(
                AuditVerificationIssue(
                    index=idx,
                    sequence_number=rec.sequence_number,
                    event_id=rec.event_id,
                    error_code="PREV_HASH_MISMATCH",
                    message=(
                        f"Broken hash link at sequence {rec.sequence_number}: "
                        f"prev_hash={rec.prev_hash[:16]}... != expected={expected_prev_hash[:16]}..."
                    ),
                )
            )

        # 4. Recompute current record hash (detects any field modification)
        recomputed_hash = rec.compute_hash()
        if not is_valid_sha256_hex(rec.record_hash) or not hmac.compare_digest(
            rec.record_hash, recomputed_hash
        ):
            issues.append(
                AuditVerificationIssue(
                    index=idx,
                    sequence_number=rec.sequence_number,
                    event_id=rec.event_id,
                    error_code="RECORD_HASH_MISMATCH",
                    message=(
                        f"Tampered audit record at sequence {rec.sequence_number}: "
                        f"stored record_hash={rec.record_hash[:16]}... != recomputed={recomputed_hash[:16]}..."
                    ),
                )
            )

        # 5. Verify Ed25519 signature if required or present
        if require_signatures or rec.signature is not None:
            if not rec.kid or not rec.signature:
                issues.append(
                    AuditVerificationIssue(
                        index=idx,
                        sequence_number=rec.sequence_number,
                        event_id=rec.event_id,
                        error_code="UNSIGNED_AUDIT_RECORD",
                        message=f"Audit record at sequence {rec.sequence_number} is missing kid or signature.",
                    )
                )
            else:
                try:
                    ver_key = mgr.get_verification_key(
                        rec.kid,
                        purpose=KeyPurpose.AUDIT,
                        record_timestamp=rec.timestamp,
                        allow_retired=allow_retired_keys,
                        clock_skew_seconds=clock_skew_seconds,
                    )
                    sig_bytes = b64url_decode(rec.signature)
                    if not ver_key.verify_signature(sig_bytes, rec.signable_bytes()):
                        issues.append(
                            AuditVerificationIssue(
                                index=idx,
                                sequence_number=rec.sequence_number,
                                event_id=rec.event_id,
                                error_code="INVALID_AUDIT_SIGNATURE",
                                message=f"Invalid Ed25519 signature on audit record at sequence {rec.sequence_number}.",
                            )
                        )
                except KeyManagementError as exc:
                    issues.append(
                        AuditVerificationIssue(
                            index=idx,
                            sequence_number=rec.sequence_number,
                            event_id=rec.event_id,
                            error_code=exc.error_code,
                            message=str(exc),
                        )
                    )
                except Exception as exc:
                    issues.append(
                        AuditVerificationIssue(
                            index=idx,
                            sequence_number=rec.sequence_number,
                            event_id=rec.event_id,
                            error_code="INVALID_SIGNATURE_ENCODING",
                            message=f"Malformed signature encoding at sequence {rec.sequence_number}: {exc}",
                        )
                    )

        expected_prev_hash = rec.record_hash
        last_valid_seq = rec.sequence_number
        last_valid_hash = rec.record_hash
        if not issues:
            verified_count += 1

    # 6. Verify against signed chain-head checkpoint if provided
    if expected_checkpoint is not None and not issues:
        if isinstance(expected_checkpoint, AuditChainCheckpoint):
            cp = expected_checkpoint
        elif isinstance(expected_checkpoint, Mapping):
            cp = AuditChainCheckpoint(
                checkpoint_id=str(expected_checkpoint["checkpoint_id"]),
                head_sequence_number=int(expected_checkpoint["head_sequence_number"]),
                head_record_hash=str(expected_checkpoint["head_record_hash"]),
                timestamp=int(expected_checkpoint["timestamp"]),
                kid=str(expected_checkpoint["kid"]),
                signature=str(expected_checkpoint["signature"]),
            )
        else:
            cp = None
            issues.append(
                AuditVerificationIssue(
                    index=total - 1,
                    sequence_number=last_valid_seq,
                    event_id=None,
                    error_code="INVALID_CHECKPOINT_FORMAT",
                    message="expected_checkpoint has invalid format.",
                )
            )

        if cp is not None:
            try:
                cp_key = mgr.get_verification_key(
                    cp.kid,
                    purpose=KeyPurpose.AUDIT,
                    record_timestamp=cp.timestamp,
                    allow_retired=allow_retired_keys,
                    clock_skew_seconds=clock_skew_seconds,
                )
                cp_sig = b64url_decode(cp.signature)
                if not cp_key.verify_signature(cp_sig, cp.signable_bytes()):
                    issues.append(
                        AuditVerificationIssue(
                            index=total - 1,
                            sequence_number=last_valid_seq,
                            event_id=None,
                            error_code="INVALID_CHECKPOINT_SIGNATURE",
                            message="Checkpoint signature verification failed.",
                        )
                    )
            except Exception as exc:
                issues.append(
                    AuditVerificationIssue(
                        index=total - 1,
                        sequence_number=last_valid_seq,
                        event_id=None,
                        error_code=getattr(exc, "error_code", "INVALID_CHECKPOINT_KEY"),
                        message=f"Checkpoint key verification failed: {exc}",
                    )
                )

            if last_valid_seq != cp.head_sequence_number:
                issues.append(
                    AuditVerificationIssue(
                        index=total - 1,
                        sequence_number=last_valid_seq,
                        event_id=None,
                        error_code="AUDIT_CHAIN_TRUNCATED",
                        message=(
                            f"Chain head sequence ({last_valid_seq}) does not match checkpoint "
                            f"sequence ({cp.head_sequence_number})."
                        ),
                    )
                )
            elif not last_valid_hash or not hmac.compare_digest(last_valid_hash, cp.head_record_hash):
                issues.append(
                    AuditVerificationIssue(
                        index=total - 1,
                        sequence_number=last_valid_seq,
                        event_id=None,
                        error_code="CHECKPOINT_HEAD_HASH_MISMATCH",
                        message="Chain head hash does not match signed checkpoint head_record_hash (chain rewrite detected).",
                    )
                )

    if issues:
        first = issues[0]
        report = AuditChainVerificationReport(
            valid=False,
            total_records=total,
            verified_records=verified_count,
            head_sequence_number=last_valid_seq,
            head_record_hash=last_valid_hash,
            first_invalid_sequence=first.sequence_number if first.sequence_number is not None else (first.index + 1),
            error_code=first.error_code,
            error_message=first.message,
            issues=tuple(issues),
        )
        if raise_on_error:
            report.raise_for_invalid()
        return report

    return AuditChainVerificationReport(
        valid=True,
        total_records=total,
        verified_records=verified_count,
        head_sequence_number=last_valid_seq,
        head_record_hash=last_valid_hash,
    )
