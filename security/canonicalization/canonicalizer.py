"""
security/canonicalization/canonicalizer.py

Reference implementation of action canonicalization and digest calculation.

DECISIONS (documented per implementation plan):
  - Domain-separation prefix: "agentshield-action-v1:"
  - Parameters dict keys are recursively sorted lexicographically.
  - Amounts and all numeric values in parameters must be passed as strings
    (e.g. "500.00") to guarantee float-free deterministic serialization.
  - Output encoding: UTF-8 JSON, compact (no extra whitespace), keys sorted.
  - Digest: lowercase hex SHA-256 of the canonical bytes.

Girish may replace this file's internals as long as the public signatures
and the above decisions remain unchanged.
"""
from __future__ import annotations

import hashlib
import json

from security.exceptions import CanonicalizationError
from security.schemas import ActionRequest

# Must match across every version of gateway and executor.
DOMAIN_PREFIX = "agentshield-action-v1:"


def _sort_recursive(obj: object) -> object:
    """Recursively sort dict keys; leave other types untouched."""
    if isinstance(obj, dict):
        return {k: _sort_recursive(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_recursive(i) for i in obj]
    return obj


def canonicalize_action(action: ActionRequest) -> bytes:
    """
    Return deterministic UTF-8 bytes for the given ActionRequest.

    The canonical form is:
        <DOMAIN_PREFIX><json>

    where <json> is compact JSON with keys sorted at every nesting level,
    and the top-level fields are always in this fixed order:
        agent_id, action_type, parameters, request_id, submitted_at, tenant_id
    """
    try:
        canonical_dict = {
            "agent_id": action.agent_id,
            "action_type": action.action_type,
            "parameters": _sort_recursive(action.parameters),
            "request_id": action.request_id,
            "submitted_at": action.submitted_at,
            "tenant_id": action.tenant_id,
        }
        json_str = json.dumps(canonical_dict, separators=(",", ":"), ensure_ascii=True)
        return (DOMAIN_PREFIX + json_str).encode("utf-8")
    except Exception as exc:
        raise CanonicalizationError(f"Failed to canonicalize action: {exc}") from exc


def calculate_action_digest(canonical_bytes: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of canonical_bytes."""
    return hashlib.sha256(canonical_bytes).hexdigest()
