"""
security/audit/chain.py
Tamper-evident audit chain construction and verification.

LIMITATION (documented per architecture review):
  verify_audit_chain() detects modification or reordering of the records
  supplied to it. It CANNOT detect:
    - Deletion of records from the chain.
    - Replacement of the entire chain.
  Do not claim stronger guarantees than this.

Chain hash formula:
  chain_hash = SHA-256(prev_chain_hash + ":" + event_bytes)
  where event_bytes = UTF-8 JSON of {event_id, event_type, event_data,
                                     actor_id, timestamp}
  and prev_chain_hash = "GENESIS" for the first record.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from security.exceptions import AuditChainError
from security.schemas import AuditChainVerificationResult, AuditRecord

GENESIS_HASH = "GENESIS"


def _compute_event_bytes(record_data: dict) -> bytes:
    """Deterministic JSON bytes of the event's content fields."""
    content = {
        "event_id": record_data["event_id"],
        "event_type": record_data["event_type"],
        "event_data": record_data["event_data"],
        "actor_id": record_data["actor_id"],
        "timestamp": record_data["timestamp"],
    }
    return json.dumps(content, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")


def _compute_chain_hash(prev_hash: str | None, event_bytes: bytes) -> str:
    prev = prev_hash if prev_hash is not None else GENESIS_HASH
    data = f"{prev}:".encode("utf-8") + event_bytes
    return hashlib.sha256(data).hexdigest()


def append_audit_record(
    event_type: str,
    event_data: dict,
    actor_id: str,
    prev_chain_hash: str | None,
) -> AuditRecord:
    """
    Build a new AuditRecord with a valid chain hash.
    Does NOT write to the database — Alok's backend persists the returned record.

    Parameters
    ----------
    prev_chain_hash : str | None
        None for the very first record; the chain_hash of the previous record
        for all subsequent records.
    """
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    record_data = {
        "event_id": event_id,
        "event_type": event_type,
        "event_data": event_data,
        "actor_id": actor_id,
        "timestamp": timestamp,
    }
    event_bytes = _compute_event_bytes(record_data)
    chain_hash = _compute_chain_hash(prev_chain_hash, event_bytes)

    return AuditRecord(
        event_id=event_id,
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        timestamp=timestamp,
        prev_chain_hash=prev_chain_hash,
        chain_hash=chain_hash,
    )


def verify_audit_chain(records: list[AuditRecord]) -> AuditChainVerificationResult:
    """
    Verify the hash chain integrity of the supplied ordered records.

    LIMITATION: Only detects modification/reordering of records within the
    supplied list. Cannot detect if records were deleted or the chain replaced.
    """
    if not records:
        return AuditChainVerificationResult(
            valid=True, verified_count=0, first_broken_index=None, error_message=None
        )

    for i, record in enumerate(records):
        expected_prev = records[i - 1].chain_hash if i > 0 else None

        # Check prev_chain_hash linkage
        if record.prev_chain_hash != expected_prev:
            return AuditChainVerificationResult(
                valid=False,
                verified_count=i,
                first_broken_index=i,
                error_message=(
                    f"Record {i} (event_id={record.event_id!r}) has "
                    f"prev_chain_hash={record.prev_chain_hash!r} but expected "
                    f"{expected_prev!r}."
                ),
            )

        # Re-compute and check chain_hash
        record_data = {
            "event_id": record.event_id,
            "event_type": record.event_type,
            "event_data": record.event_data,
            "actor_id": record.actor_id,
            "timestamp": record.timestamp,
        }
        event_bytes = _compute_event_bytes(record_data)
        expected_hash = _compute_chain_hash(expected_prev, event_bytes)

        if record.chain_hash != expected_hash:
            return AuditChainVerificationResult(
                valid=False,
                verified_count=i,
                first_broken_index=i,
                error_message=(
                    f"Record {i} (event_id={record.event_id!r}) has "
                    f"chain_hash={record.chain_hash!r} but computed "
                    f"{expected_hash!r}. Record may have been tampered."
                ),
            )

    return AuditChainVerificationResult(
        valid=True,
        verified_count=len(records),
        first_broken_index=None,
        error_message=None,
    )
